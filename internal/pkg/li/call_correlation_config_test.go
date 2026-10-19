package li

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestCallCorrelationConfigDefaultsAndIndependentSwitches(t *testing.T) {
	cfg := CallCorrelationConfig{}.Normalized()
	require.NoError(t, cfg.Validate())
	require.False(t, cfg.Enabled())
	require.Equal(t, DefaultCallCorrelationConfig(), cfg)
	for _, enable := range []func(*CallCorrelationConfig){func(c *CallCorrelationConfig) { c.SessionHeaders = []string{"X-Session"} }, func(c *CallCorrelationConfig) { c.ParentCallIDHeaders = []string{"X-Parent"} }, func(c *CallCorrelationConfig) { c.SDPOriginMatching = true }, func(c *CallCorrelationConfig) { c.AddressChaining = true }, func(c *CallCorrelationConfig) { c.AddressChainingRewritten = true }, func(c *CallCorrelationConfig) { c.NumberChaining = true }} {
		c := cfg
		enable(&c)
		require.True(t, c.Enabled())
		require.NoError(t, c.Validate())
	}
}
func TestCallCorrelationConfigRejectsInvalidBoundsAndNames(t *testing.T) {
	tests := map[string]func(*CallCorrelationConfig){
		"wait timeout":      func(c *CallCorrelationConfig) { c.WaitTimeout = -time.Second },
		"shutdown timeout":  func(c *CallCorrelationConfig) { c.ShutdownTimeout = -time.Second },
		"duration":          func(c *CallCorrelationConfig) { c.AddressWindow = -time.Second },
		"records":           func(c *CallCorrelationConfig) { c.MaxRecords = -1 },
		"candidate ceiling": func(c *CallCorrelationConfig) { c.MaxCandidates = 1_000_001 },
		"origin ceiling":    func(c *CallCorrelationConfig) { c.SDPOriginMaxTracked = 1_000_001 },
		"origin history window": func(c *CallCorrelationConfig) {
			c.SDPOriginMatching = true
			c.SDPOriginObservationTTL = c.SDPOriginReuseWindow
		},
		"header injection": func(c *CallCorrelationConfig) { c.SessionHeaders = []string{"X-Test\r\n"} },
		"header duplicate": func(c *CallCorrelationConfig) {
			c.SessionHeaders = []string{"X-Test"}
			c.ParentCallIDHeaders = []string{"x-test"}
		},
		"header count": func(c *CallCorrelationConfig) {
			for i := 0; i < 33; i++ {
				c.SessionHeaders = append(c.SessionHeaders, "X-Test")
			}
		},
		"singleton alias":        func(c *CallCorrelationConfig) { c.NodeAliases = [][]string{{"192.0.2.1"}} },
		"invalid alias":          func(c *CallCorrelationConfig) { c.NodeAliases = [][]string{{"192.0.2.1", "example.test"}} },
		"duplicate mapped alias": func(c *CallCorrelationConfig) { c.NodeAliases = [][]string{{"192.0.2.1", "::ffff:192.0.2.1"}} },
		"duplicate alias sets": func(c *CallCorrelationConfig) {
			c.NodeAliases = [][]string{{"192.0.2.1", "192.0.2.2"}, {"192.0.2.2", "192.0.2.3"}}
		},
		"path nul": func(c *CallCorrelationConfig) { c.StoreFile = "store\x00" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			change(&cfg)
			require.Error(t, cfg.Validate())
		})
	}
}
func TestCallCorrelationConfigRequiresValidPersistentKeys(t *testing.T) {
	valid := DefaultCallCorrelationConfig()
	valid.StoreFile = "correlation.enc"
	valid.StoreKeys = securestore.KeyConfig{Active: securestore.KeyRef{ID: "active", File: "active.key"}, Prior: []securestore.KeyRef{{ID: "prior", File: "prior.key"}}}
	require.NoError(t, valid.Validate(), "configuration validation performs no filesystem access")
	for name, change := range map[string]func(*CallCorrelationConfig){
		"missing keys":        func(c *CallCorrelationConfig) { c.StoreKeys = securestore.KeyConfig{} },
		"missing active file": func(c *CallCorrelationConfig) { c.StoreKeys.Active.File = "" },
		"missing active id":   func(c *CallCorrelationConfig) { c.StoreKeys.Active.ID = "" },
		"invalid id":          func(c *CallCorrelationConfig) { c.StoreKeys.Active.ID = "secret/path" },
		"duplicate id":        func(c *CallCorrelationConfig) { c.StoreKeys.Prior[0].ID = c.StoreKeys.Active.ID },
		"prior ceiling":       func(c *CallCorrelationConfig) { c.StoreKeys.Prior = make([]securestore.KeyRef, 5) },
		"path nul":            func(c *CallCorrelationConfig) { c.StoreKeys.Active.File = "key\x00" },
		"invalid legacy id":   func(c *CallCorrelationConfig) { c.StoreKeys.LegacyID = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			cfg.StoreKeys.Prior = append([]securestore.KeyRef(nil), valid.StoreKeys.Prior...)
			change(&cfg)
			require.Error(t, cfg.Validate())
		})
	}
}

func TestCallCorrelationConfigIdentityAndWaitingDoNotEnableMatching(t *testing.T) {
	c := DefaultCallCorrelationConfig()
	c.ResponseWait = true
	c.IdentityProfiles = []CorrelationIdentityProfile{{Name: "example", Namespace: "example", SIPHosts: []string{"sip.example"}}}
	require.NoError(t, c.Validate())
	require.False(t, c.Enabled())
	c.ResponseWait = false
	require.False(t, c.Normalized().ResponseWait)
	for _, change := range []func(*CallCorrelationConfig){func(c *CallCorrelationConfig) { c.ResponseWaitWindow = -1 }, func(c *CallCorrelationConfig) { c.MaxPendingDialogs = -1 }, func(c *CallCorrelationConfig) { c.MaxPendingPackets = 1000001 }, func(c *CallCorrelationConfig) { c.MaxPendingBytes = 1<<30 + 1 }} {
		bad := c
		change(&bad)
		require.Error(t, bad.Validate())
	}
}
func TestCallCorrelationConfigRejectsInvalidIdentityProfiles(t *testing.T) {
	base := CorrelationIdentityProfile{Name: "example", Namespace: "tenant", SIPHosts: []string{"sip.example"}}
	for _, change := range []func(*CorrelationIdentityProfile){
		func(p *CorrelationIdentityProfile) { p.Name = "" }, func(p *CorrelationIdentityProfile) { p.Namespace = "" }, func(p *CorrelationIdentityProfile) { p.SIPHosts = nil }, func(p *CorrelationIdentityProfile) { p.SIPHosts = []string{"*.example"} }, func(p *CorrelationIdentityProfile) { p.SIPHosts = []string{"sip.example", "SIP.EXAMPLE"} },
		func(p *CorrelationIdentityProfile) { p.InternationalPrefixes = []string{"+"} }, func(p *CorrelationIdentityProfile) {
			p.RewriteRules = []CorrelationIdentityRewrite{{Pattern: `99([0-9]+)$`, Replacement: `$1`}}
		}, func(p *CorrelationIdentityProfile) {
			p.RewriteRules = []CorrelationIdentityRewrite{{Pattern: `^99(?=123)$`, Replacement: `123`}}
		}, func(p *CorrelationIdentityProfile) {
			p.RewriteRules = []CorrelationIdentityRewrite{{Pattern: `^99([0-9]+)$`, Replacement: `${missing}`}}
		},
	} {
		p := base
		change(&p)
		c := DefaultCallCorrelationConfig()
		c.IdentityProfiles = []CorrelationIdentityProfile{p}
		require.Error(t, c.Validate())
	}
	c := DefaultCallCorrelationConfig()
	c.IdentityProfiles = []CorrelationIdentityProfile{base, base}
	require.Error(t, c.Validate())
}

func TestCallCorrelationConfigIdentityProfileBounds(t *testing.T) {
	p := CorrelationIdentityProfile{Name: "example", Namespace: "example", SIPHosts: []string{"sip.example"}}
	for _, change := range []func(*CorrelationIdentityProfile){func(p *CorrelationIdentityProfile) { p.Namespace = "bad\x01" }, func(p *CorrelationIdentityProfile) { p.PhoneContexts = []string{"+"} }, func(p *CorrelationIdentityProfile) { p.SIPHosts = []string{"sip.example:bad"} }, func(p *CorrelationIdentityProfile) { p.RewriteRules = make([]CorrelationIdentityRewrite, 17) }, func(p *CorrelationIdentityProfile) { p.InternationalPrefixes = make([]string, 17) }, func(p *CorrelationIdentityProfile) {
		p.RewriteRules = []CorrelationIdentityRewrite{{Pattern: `^([0-9]+)$`, Replacement: `alice`}}
	}, func(p *CorrelationIdentityProfile) {
		p.RewriteRules = []CorrelationIdentityRewrite{{Pattern: `^([0-9]+)$`, Replacement: ``}}
	}} {
		v := p
		change(&v)
		c := DefaultCallCorrelationConfig()
		c.IdentityProfiles = []CorrelationIdentityProfile{v}
		require.Error(t, c.Validate())
	}
	c := DefaultCallCorrelationConfig()
	c.IdentityProfiles = make([]CorrelationIdentityProfile, 33)
	require.Error(t, c.Validate())
}
