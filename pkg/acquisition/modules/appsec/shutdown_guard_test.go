package appsecacquisition

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
)

// newShutdownTestSource builds the smallest Source that appsecHandler can
// serve a request with: auth is bypassed by seeding the cache with a valid
// unexpired key, and the appsec runtime only needs the body settings (no
// rules are loaded, so a runner answers with the default pass response).
func newShutdownTestSource(t *testing.T) *Source {
	t.Helper()

	logger := log.New()
	logger.SetOutput(io.Discard)

	w := &Source{
		logger:     log.NewEntry(logger),
		lapiURL:    "",
		AuthCache:  NewAuthCache(),
		httpClient: &http.Client{},
		InChan:     make(chan appsec.ParsedRequest),
		stopChan:   make(chan struct{}),
		AppsecRuntime: &appsec.AppsecRuntimeConfig{
			// Minimal runtime: no rules are loaded, so a runner answers
			// with the default pass response. Only BodySettings is read by
			// the request parsing path, and GenerateResponse reads the
			// status codes from Config.
			BodySettings: appsec.BodySettings{
				MaxSize: appsec.DefaultMaxBodySize,
				Action:  appsec.BodySizeActionDrop,
			},
			Config: &appsec.AppsecConfig{
				UserPassedHTTPCode:    http.StatusOK,
				BouncerPassedHTTPCode: http.StatusOK,
			},
		},
		config: Configuration{
			AuthCacheDuration: ptr.Of(time.Minute),
			BodyReadTimeout:   ptr.Of(time.Second),
		},
	}
	w.AuthCache.Set("test-key", time.Now().Add(time.Minute))

	return w
}

// appsecTestRequest builds a minimal valid inspection request: the headers
// NewParsedRequestFromRequest demands (client IP, URI, verb).
func appsecTestRequest(t *testing.T, target string) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, target, http.NoBody)
	require.NoError(t, err)
	req.Header.Set(appsec.APIKeyHeaderName, "test-key")
	req.Header.Set(appsec.IPHeaderName, "1.2.3.4")
	req.Header.Set(appsec.URIHeaderName, "/")
	req.Header.Set(appsec.VerbHeaderName, "GET")

	return req
}

// serveOne runs appsecHandler for a single request on a fresh goroutine and
// returns a channel yielding the recorded status code.
func serveOne(w *Source, req *http.Request) <-chan int {
	// appsecHandler writes the status via rw.WriteHeader; rec.CloseNotify is
	// irrelevant here. The recorder captures the first WriteHeader call.
	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		w.appsecHandler(rec, req)
		done <- rec.Code
	}()
	return done
}

// TestAppsecHandlerAbortsWhenSourceIsStopping covers the reload hang from
// #4739: a request that is in flight while the runners are being stopped
// must not block forever on the unbuffered InChan send. The handler has to
// answer with 503 once the source signals it is stopping.
func TestAppsecHandlerAbortsWhenSourceIsStopping(t *testing.T) {
	w := newShutdownTestSource(t)

	// No runner is reading InChan: a blocked send would hang forever.
	close(w.stopChan)

	status := <-serveOne(w, appsecTestRequest(t, "http://appsec.local/"))

	assert.Equal(t, http.StatusServiceUnavailable, status)
}

// TestAppsecHandlerAbortsWhileWaitingForResponse covers the second wedge of
// #4739: the request reached a runner before the reload, but the runner exits
// (t.Dying) before answering, so nothing will ever send on ResponseChannel.
// The handler must abandon the wait and answer 503 instead of blocking
// server.Shutdown forever.
func TestAppsecHandlerAbortsWhileWaitingForResponse(t *testing.T) {
	w := newShutdownTestSource(t)

	// A runner accepts the request...
	go func() {
		request := <-w.InChan
		_ = request
		// ...and then dies without answering (SIGHUP reload path: runners
		// return on t.Dying() and never touch ResponseChannel again).
	}()

	// Give the accepting goroutine a moment to take the request first, so
	// the wait branch (not the send branch) is the one being exercised,
	// then signal the stop exactly like listenAndServe does on reload.
	time.Sleep(50 * time.Millisecond)
	close(w.stopChan)

	select {
	case status := <-serveOne(w, appsecTestRequest(t, "http://appsec.local/")):
		assert.Equal(t, http.StatusServiceUnavailable, status)
	case <-time.After(5 * time.Second):
		t.Fatal("handler stayed wedged on the response wait after the source stopped")
	}
}

// TestAppsecHandlerServesRequestDuringNormalOperation pins the happy path:
// with a live runner and no shutdown, the request is answered normally and
// the guard channels stay transparent.
func TestAppsecHandlerServesRequestDuringNormalOperation(t *testing.T) {
	w := newShutdownTestSource(t)

	// One-shot runner: accept the request and answer with the default
	// pass response, exactly like AppsecRunner.handleRequest does for an
	// empty ruleset.
	go func() {
		request := <-w.InChan
		request.ResponseChannel <- appsec.AppsecTempResponse{Action: appsec.AllowRemediation}
	}()

	done := serveOne(w, appsecTestRequest(t, "http://appsec.local/"))

	select {
	case status := <-done:
		assert.Equal(t, http.StatusOK, status)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not answer within 5s")
	}
}

// TestAppsecShutdownCompletesWithInFlightRequest reproduces the full deadlock
// from #4739 at the server level: a request is inside appsecHandler (blocked
// on InChan, no runner left), and the server is being gracefully shut down
// exactly like listenAndServe does during a SIGHUP reload. On main this
// wedges forever; with the stopChan guard the shutdown returns.
func TestAppsecShutdownCompletesWithInFlightRequest(t *testing.T) {
	w := newShutdownTestSource(t)

	// No runner: an in-flight request would wedge the unbuffered InChan.
	done := serveOne(w, appsecTestRequest(t, "http://appsec.local/"))

	// Give the request a moment to reach the send, then stop the source
	// the same way listenAndServe does on t.Dying().
	time.Sleep(50 * time.Millisecond)
	close(w.stopChan)

	// Graceful shutdown of a real http.Server whose only connection is the
	// wedged request: it must complete (the handler aborts on stopChan)
	// instead of waiting for the connection forever.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.appsecHandler(rw, r)
	})}
	go func() { _ = server.Serve(listener) }()

	// Fire a second request into the real server so there is an actual
	// tracked connection for Shutdown to wait on.
	go func() {
		resp, err := http.Get("http://" + listener.Addr().String() + "/")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	// Let the request reach the wedged send before shutting down.
	time.Sleep(50 * time.Millisecond)

	stopCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	err = server.Shutdown(stopCtx)
	require.NoError(t, err, "shutdown must not time out while a request is wedged")

	select {
	case status := <-done:
		assert.Equal(t, http.StatusServiceUnavailable, status)
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request was not aborted by the shutdown")
	}
}
