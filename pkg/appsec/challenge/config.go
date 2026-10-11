// config.go defines the YAML-facing challenge configuration. Multiple
// appsec-config files can each contribute a disjoint subset; MergeFrom
// composes them without one wiping the others. Once merged, BuildOptions
// translates the Config into the runtime's functional-option list
// (NewChallengeRuntime(...)).

package challenge

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
)

// Config carries the YAML-configurable challenge runtime settings.
type Config struct {
	// MasterSecret is the long-lived secret all per-epoch HMAC keys and the
	// cookie-sealing AES key derive from. In a distributed deployment every
	// instance MUST share the same value to sign/verify each other's
	// challenges. If unset, the runtime generates an ephemeral random secret
	// at startup — fine for a single instance, but restarts then invalidate
	// outstanding cookies.
	MasterSecret *string `yaml:"master_secret"`

	// KeyRotationInterval is the per-epoch key advance period. All instances
	// in a distributed setup MUST agree on it to derive identical keys.
	// Defaults to 5m.
	KeyRotationInterval *time.Duration `yaml:"key_rotation_interval"`

	// MaxLiveEpochs is how many past epochs (besides the current one) the
	// keyring keeps accepting, so in-flight submissions aren't invalidated at
	// a rotation boundary. Bounds ticket-forgery exposure to
	// MaxLiveEpochs × KeyRotationInterval. Defaults to 3.
	MaxLiveEpochs *int `yaml:"max_live_epochs"`

	// CookieTTL is how long a successful-challenge cookie stays valid.
	// Decoupled from the keyring window (enforced by a not_after stamp inside
	// the sealed cookie, not key eviction) so cookies can be long-lived while
	// per-epoch keys rotate tightly. Defaults to 12h.
	CookieTTL *time.Duration `yaml:"cookie_ttl"`

	// CookieSameSite overrides the challenge cookies' SameSite attribute
	// (lax, strict or none). The default, lax, works for top-level navigation
	// but browsers reject lax cookies in a cross-site iframe, so an app
	// embedded in an approved third-party page needs "none" for the challenge
	// to clear there. SameSite=None requires the request to be https (the
	// runtime refuses to mint a non-secure SameSite=None cookie).
	CookieSameSite *string `yaml:"cookie_same_site"`

	// CookiePartitioned opts the challenge cookies into CHIPS: the cookie is
	// scoped to the top-level site doing the embedding, so clearance granted
	// inside a cross-site iframe is not shared with other embedders. Requires
	// cookie_same_site "none"; enabling it with lax/strict is a config error
	// (a partitioned lax cookie is still rejected in the iframe, so the
	// operator would get a challenge that can never clear). Defaults to false.
	CookiePartitioned *bool `yaml:"cookie_partitioned"`

	// CustomJSTimeout bounds the time all CUSTOM_JS detection hooks get, in
	// total rather than each.
	// Defaults to DefaultCustomJSTimeout.
	CustomJSTimeout *time.Duration `yaml:"custom_js_timeout"`

	// MaxCookieSize caps the challenge cookie's encoded size, enforced on both
	// seal and open. It bounds the memory allocated from the (attacker-supplied)
	// fingerprint envelope, closing an over-allocation DoS. Defaults to
	// MaxCookieLen (4096, the per-cookie size browsers guarantee); raise it only
	// if a non-browser client tolerates larger cookies.
	MaxCookieSize *int `yaml:"max_cookie_size"`

	// CryptoObfuscationPoolSize is how many obfuscations of the per-epoch
	// sign-key module to keep per live epoch. Each variant embeds the same key
	// with different byte layout, giving per-visitor variance. Defaults to 1.
	CryptoObfuscationPoolSize *int `yaml:"crypto_obfuscation_pool_size"`

	// SpentSetMaxEntries caps the replay-protection LRU. A deep DoS backstop;
	// steady-state stays far below it. Defaults to spentSetDefaultMaxEntries.
	SpentSetMaxEntries *int `yaml:"spent_set_max_entries"`

	// LogLevel sets the challenge runtime's own log verbosity, independent of
	// the global level. Note: `panic` is not supported — logrus.PanicLevel is 0,
	// which SubLogger (pkg/logging/sublogger.go) treats as "inherit the parent level".
	LogLevel *log.Level `yaml:"log_level,omitempty"`
}

// MergeFrom overlays the non-nil fields of other onto c, field by field, so
// multiple appsec-configs can each contribute a disjoint subset (last non-nil
// wins). A nil receiver or argument is a no-op.
func (c *Config) MergeFrom(other *Config) {
	if c == nil || other == nil {
		return
	}

	if other.MasterSecret != nil {
		c.MasterSecret = other.MasterSecret
	}
	if other.KeyRotationInterval != nil {
		c.KeyRotationInterval = other.KeyRotationInterval
	}
	if other.MaxLiveEpochs != nil {
		c.MaxLiveEpochs = other.MaxLiveEpochs
	}
	if other.CookieTTL != nil {
		c.CookieTTL = other.CookieTTL
	}
	if other.CookieSameSite != nil {
		c.CookieSameSite = other.CookieSameSite
	}
	if other.CookiePartitioned != nil {
		c.CookiePartitioned = other.CookiePartitioned
	}
	if other.CustomJSTimeout != nil {
		c.CustomJSTimeout = other.CustomJSTimeout
	}
	if other.MaxCookieSize != nil {
		c.MaxCookieSize = other.MaxCookieSize
	}
	if other.CryptoObfuscationPoolSize != nil {
		c.CryptoObfuscationPoolSize = other.CryptoObfuscationPoolSize
	}
	if other.SpentSetMaxEntries != nil {
		c.SpentSetMaxEntries = other.SpentSetMaxEntries
	}
	if other.LogLevel != nil {
		c.LogLevel = other.LogLevel
	}
}

// BuildOptions translates a (possibly nil) merged Config into the WithXxx
// Option list for NewChallengeRuntime; unset fields are omitted so the runtime
// uses its built-in defaults. Returns an error if MasterSecret is set but
// invalid. parent (may be nil) is the logger the "challenge" sublogger derives
// from, at the configured log_level or parent's level.
func BuildOptions(c *Config, parent *log.Entry) ([]Option, error) {
	// Always give the runtime its own component sublogger.
	base := log.StandardLogger()
	if parent != nil {
		base = parent.Logger
	}

	var lvl log.Level
	if c != nil && c.LogLevel != nil {
		lvl = *c.LogLevel
	}

	opts := []Option{WithLogger(logging.SubLogger(base, "challenge", lvl))}

	if c == nil {
		return opts, nil
	}

	if c.MasterSecret != nil && *c.MasterSecret != "" {
		secret, err := ParseConfiguredSecret(*c.MasterSecret)
		if err != nil {
			return nil, fmt.Errorf("invalid challenge master_secret: %w", err)
		}
		opts = append(opts, WithMasterSecret(secret))
	}
	if c.KeyRotationInterval != nil {
		opts = append(opts, WithRotationInterval(*c.KeyRotationInterval))
	}
	if c.MaxLiveEpochs != nil && *c.MaxLiveEpochs > 0 {
		opts = append(opts, WithMaxLiveEpochs(*c.MaxLiveEpochs))
	}
	if c.CookieTTL != nil {
		opts = append(opts, WithCookieTTL(*c.CookieTTL))
	}
	if c.CookieSameSite != nil || c.CookiePartitioned != nil {
		sameSite := ""
		if c.CookieSameSite != nil {
			sameSite = *c.CookieSameSite
		}
		partitioned := c.CookiePartitioned != nil && *c.CookiePartitioned
		if partitioned && !strings.EqualFold(sameSite, cookie.SameSiteNone) {
			return nil, fmt.Errorf(
				"invalid challenge cookie settings: cookie_partitioned requires cookie_same_site %q (a partitioned %q cookie is still rejected in a cross-site iframe)",
				cookie.SameSiteNone, sameSiteOrLax(sameSite))
		}
		switch strings.ToLower(sameSite) {
		case "", strings.ToLower(cookie.SameSiteLax), strings.ToLower(cookie.SameSiteStrict), strings.ToLower(cookie.SameSiteNone):
		default:
			return nil, fmt.Errorf("invalid challenge cookie_same_site %q (expected lax, strict or none)", sameSite)
		}
		opts = append(opts, WithCookiePolicy(sameSite, partitioned))
	}
	if c.CustomJSTimeout != nil {
		opts = append(opts, WithCustomJSTimeout(*c.CustomJSTimeout))
	}
	if c.MaxCookieSize != nil && *c.MaxCookieSize > 0 {
		opts = append(opts, WithMaxCookieLen(*c.MaxCookieSize))
	}
	if c.CryptoObfuscationPoolSize != nil && *c.CryptoObfuscationPoolSize > 0 {
		opts = append(opts, WithCryptoObfuscationPoolSize(*c.CryptoObfuscationPoolSize))
	}
	if c.SpentSetMaxEntries != nil && *c.SpentSetMaxEntries > 0 {
		opts = append(opts, WithSpentSetMaxEntries(*c.SpentSetMaxEntries))
	}

	return opts, nil
}

// sameSiteOrLax returns the given SameSite mode, or "Lax" when empty, for
// error messages that must name the effective mode rather than an empty one.
func sameSiteOrLax(mode string) string {
	if mode == "" {
		return cookie.SameSiteLax
	}
	return mode
}
