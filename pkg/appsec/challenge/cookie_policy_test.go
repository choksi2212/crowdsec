package challenge

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
)

// TestBuildOptionsCookiePolicy covers the cookie_same_site /
// cookie_partitioned surface: the values must reach the runtime, the
// partitioned-without-none combination must be refused at config time (a
// partitioned lax cookie is still rejected inside a cross-site iframe, so
// accepting the combination would give the operator a challenge that can
// never clear), and an unknown mode must be refused too.
func TestBuildOptionsCookiePolicy(t *testing.T) {
	t.Run("valid policy reaches the runtime", func(t *testing.T) {
		cfg := &Config{
			MasterSecret:      new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			CookieSameSite:    new("none"),
			CookiePartitioned: new(true),
		}

		opts, err := BuildOptions(cfg, nil)
		require.NoError(t, err)

		rt, err := NewChallengeRuntime(t.Context(), append(opts, withoutPreWarm())...)
		require.NoError(t, err)

		assert.Equal(t, "none", rt.cookieSameSite, "cookie_same_site must reach the runtime")
		assert.True(t, rt.cookiePartitioned, "cookie_partitioned must reach the runtime")
	})

	t.Run("partitioned without none is a config error", func(t *testing.T) {
		cfg := &Config{
			MasterSecret:      new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			CookiePartitioned: new(true),
		}

		_, err := BuildOptions(cfg, nil)
		require.Error(t, err, "partitioned + default lax must be refused")
		assert.Contains(t, err.Error(), "cookie_partitioned requires cookie_same_site")
	})

	t.Run("partitioned with explicit lax is a config error", func(t *testing.T) {
		cfg := &Config{
			MasterSecret:      new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			CookieSameSite:    new("lax"),
			CookiePartitioned: new(true),
		}

		_, err := BuildOptions(cfg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cookie_partitioned requires cookie_same_site")
	})

	t.Run("unknown mode is refused", func(t *testing.T) {
		cfg := &Config{
			MasterSecret:   new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			CookieSameSite: new("sometimes"),
		}

		_, err := BuildOptions(cfg, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid challenge cookie_same_site")
	})

	t.Run("unconfigured runtime keeps the lax default", func(t *testing.T) {
		rt, err := NewChallengeRuntime(t.Context(),
			WithMasterSecret([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
			withoutPreWarm())
		require.NoError(t, err)

		assert.Equal(t, cookie.SameSiteLax, rt.cookieSameSite, "default must stay Lax")
		assert.False(t, rt.cookiePartitioned)
	})
}

// TestSealedCookiesCarryConfiguredPolicy seals a real allowlist cookie on a
// runtime configured for the embedded case and asserts the rendered
// Set-Cookie carries SameSite=None + Secure + Partitioned, while the default
// runtime keeps rendering SameSite=Lax unpartitioned. This is the wire-level
// behavior the reporter's iframe needs.
func TestSealedCookiesCarryConfiguredPolicy(t *testing.T) {
	req := &http.Request{
		Header: http.Header{"User-Agent": []string{"test-agent"}},
		URL:    mustURL("https://example.test/protected"),
	}

	t.Run("default runtime seals Lax cookies", func(t *testing.T) {
		rt, err := NewChallengeRuntime(t.Context(),
			WithMasterSecret([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
			withoutPreWarm())
		require.NoError(t, err)

		ck, err := rt.SealAllowlistCookie(req, "embedded-check", nil)
		require.NoError(t, err)

		rendered := ck.String()
		assert.Contains(t, rendered, "SameSite=Lax")
		assert.NotContains(t, rendered, "Partitioned")
	})

	t.Run("embedded runtime seals None + Secure + Partitioned", func(t *testing.T) {
		rt, err := NewChallengeRuntime(t.Context(),
			WithMasterSecret([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
			WithCookiePolicy("none", true),
			withoutPreWarm())
		require.NoError(t, err)

		ck, err := rt.SealAllowlistCookie(req, "embedded-check", nil)
		require.NoError(t, err)

		rendered := ck.String()
		assert.Contains(t, rendered, "SameSite=None", "the iframe case needs SameSite=None")
		assert.Contains(t, rendered, "Secure", "SameSite=None requires Secure")
		assert.Contains(t, rendered, "Partitioned", "cookie_partitioned must render the CHIPS attribute")
		assert.Contains(t, rendered, "HttpOnly", "the sealed challenge cookie stays HttpOnly")
	})
}

// TestChallengePageProbeMirrorsCookiePolicy renders the challenge page on a
// runtime configured for embedding and asserts the in-page cookie-support
// probe uses the configured mode: the probe's throwaway cookie is subject to
// the same browser rules as the real one, so a lax probe inside a
// none-required iframe would spuriously report "cookies disabled".
func TestChallengePageProbeMirrorsCookiePolicy(t *testing.T) {
	rt, err := NewChallengeRuntime(t.Context(),
		WithMasterSecret([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
		WithCookiePolicy("none", true),
		withoutPreWarm())
	require.NoError(t, err)

	page, err := rt.GetChallengePage(t.Context(), "test-agent", 0)
	require.NoError(t, err)

	// The template source must drive the probe through the CookieSameSite
	// value (not a hardcoded SameSite=Lax), so the configured mode survives
	// template edits. Execute resolves the action, so this check reads the
	// embedded template file itself.
	tmplSrc, err := os.ReadFile("challenge.html.tmpl")
	require.NoError(t, err, "the challenge page template must ship with the package")
	assert.Contains(t, string(tmplSrc), `SameSite={{.CookieSameSite}}`,
		"the probe must be driven by the template's CookieSameSite value")

	// The rendered page must carry the configured mode, not the literal
	// action and not an empty SameSite= attribute: browsers treat a missing
	// value as no attribute at all, which re-breaks the iframe case.
	require.NotContains(t, page, "SameSite={{", "the CookieSameSite template value must be resolved, not echoed verbatim")
	rendered := extractProbeLine(t, page)
	assert.Contains(t, rendered, "SameSite=none", "the probe line must carry the configured mode")

	// A default (lax) runtime must render a lax probe, pinning the
	// default-path behavior the fix leaves untouched.
	defaultRT, err := NewChallengeRuntime(t.Context(),
		WithMasterSecret([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
		withoutPreWarm())
	require.NoError(t, err)
	defaultPage, err := defaultRT.GetChallengePage(t.Context(), "test-agent", 0)
	require.NoError(t, err)
	assert.Contains(t, extractProbeLine(t, defaultPage), "SameSite="+cookie.SameSiteLax,
		"the unconfigured runtime must keep the lax probe")
}

// extractProbeLine returns the cookiesEnabled probe's document.cookie line
// from a rendered challenge page, so the test fails with the actual line on
// mismatch instead of a page-wide Contains.
func extractProbeLine(t *testing.T, page string) string {
	t.Helper()
	for line := range strings.SplitSeq(page, "\n") {
		if strings.Contains(line, `__crowdsec_cookie_test=1;`) {
			return strings.TrimSpace(line)
		}
	}
	t.Fatal("cookie-support probe line not found in rendered challenge page")
	return ""
}
