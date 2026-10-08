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
