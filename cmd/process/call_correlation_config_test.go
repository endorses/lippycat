//go:build (processor || all) && li

package process

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func resetLICorrelationViper(t *testing.T) {
	t.Helper()
	previous := *viper.GetViper()
	t.Cleanup(func() { *viper.GetViper() = previous })
	viper.Reset()
	bindLICallCorrelationEnvironment()
}

func TestLICallCorrelationDefaults(t *testing.T) {
	resetLICorrelationViper(t)
	config, err := readLICallCorrelationConfig()
	require.NoError(t, err)
	require.Equal(t, li.DefaultCallCorrelationConfig(), config)
	require.False(t, config.Enabled())
	require.Equal(t, config, GetLIConfig().CallCorrelation)
}

func TestLICallCorrelationYAMLAndEnvironment(t *testing.T) {
	resetLICorrelationViper(t)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`processor:
  li:
    correlation:
      session_headers: [Session-ID, P-Charging-Vector, X-Proprietary-Session-ID]
      parent_call_id_headers: [Parent-Call-ID]
      sdp_origin_matching: true
      sdp_origin_reuse_window: 20s
      sdp_origin_observation_ttl: 3m
      sdp_origin_suspend: 4m
      sdp_origin_max_tracked: 200
      address_chaining: true
      address_chaining_rewritten: true
      number_chaining: true
      address_window: 1500ms
      number_window: 750ms
      node_aliases: [[192.0.2.1, 192.0.2.2], ['2001:db8::1', '2001:db8::2']]
      decision_horizon: 6m
      terminal_grace: 40s
      wait_timeout: 2s
      shutdown_timeout: 7s
      store_file: /protected/correlation.store
      store_key_id: correlation-v2
      store_key_file: /protected/correlation.key
      store_read_keys: [correlation-v1=/protected/old.key]
      max_candidates: 300
      max_records: 400
`)))
	expected := li.CallCorrelationConfig{
		SessionHeaders:      []string{"Session-ID", "P-Charging-Vector", "X-Proprietary-Session-ID"},
		ParentCallIDHeaders: []string{"Parent-Call-ID"}, SDPOriginMatching: true,
		SDPOriginReuseWindow: 20 * time.Second, SDPOriginObservationTTL: 3 * time.Minute,
		SDPOriginSuspend: 4 * time.Minute, SDPOriginMaxTracked: 200,
		AddressChaining: true, AddressChainingRewritten: true, NumberChaining: true,
		AddressWindow: 1500 * time.Millisecond, NumberWindow: 750 * time.Millisecond,
		NodeAliases:     [][]string{{"192.0.2.1", "192.0.2.2"}, {"2001:db8::1", "2001:db8::2"}},
		DecisionHorizon: 6 * time.Minute, TerminalGrace: 40 * time.Second,
		WaitTimeout: 2 * time.Second, ShutdownTimeout: 7 * time.Second,
		ResponseWaitWindow: 5 * time.Millisecond, MaxPendingDialogs: 1000, MaxPendingPackets: 10000, MaxPendingBytes: 16 << 20,
		StoreFile: "/protected/correlation.store",
		StoreKeys: securestore.KeyConfig{Active: securestore.KeyRef{ID: "correlation-v2", File: "/protected/correlation.key"}, Prior: []securestore.KeyRef{{ID: "correlation-v1", File: "/protected/old.key"}}}, MaxCandidates: 300, MaxRecords: 400,
	}
	actual, err := readLICallCorrelationConfig()
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	var runtime processor.Config
	require.NoError(t, applyLICallCorrelationConfig(&runtime))
	require.Equal(t, expected, runtime.LICallCorrelation)

	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_SESSION_HEADERS", `["Session-ID","X-Session"]`)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_PARENT_CALL_ID_HEADERS", "Parent-Call-ID,X-Parent")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_NODE_ALIASES", `[["192.0.2.3","192.0.2.4"]]`)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_SDP_ORIGIN_MATCHING", "false")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_ADDRESS_WINDOW", "0.8s")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_WAIT_TIMEOUT", "3s")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_SHUTDOWN_TIMEOUT", "8s")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_MAX_RECORDS", "500")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_STORE_FILE", "/protected/env.store")
	expected.SessionHeaders = []string{"Session-ID", "X-Session"}
	expected.ParentCallIDHeaders = []string{"Parent-Call-ID", "X-Parent"}
	expected.NodeAliases = [][]string{{"192.0.2.3", "192.0.2.4"}}
	expected.SDPOriginMatching = false
	expected.AddressWindow = 800 * time.Millisecond
	expected.WaitTimeout = 3 * time.Second
	expected.ShutdownTimeout = 8 * time.Second
	expected.MaxRecords = 500
	expected.StoreFile = "/protected/env.store"
	actual, err = readLICallCorrelationConfig()
	require.NoError(t, err)
	require.Equal(t, expected, actual, "environment overrides YAML including explicit false")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_SESSION_HEADERS", "[]")
	actual, err = readLICallCorrelationConfig()
	require.NoError(t, err)
	require.Empty(t, actual.SessionHeaders, "empty JSON list disables H")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_STORE_READ_KEYS", `"old=/protected/path,with-comma"`)
	actual, err = readLICallCorrelationConfig()
	require.NoError(t, err)
	require.Equal(t, []securestore.KeyRef{{ID: "old", File: "/protected/path,with-comma"}}, actual.StoreKeys.Prior)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_STORE_READ_KEYS", "")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_STORE_FILE", "")
	actual, err = readLICallCorrelationConfig()
	require.NoError(t, err)
	require.Empty(t, actual.StoreKeys.Prior)
	require.Empty(t, actual.StoreFile, "explicit empty environment disables persistence")
}

func TestLICallCorrelationRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, key string
		value     any
	}{
		{"duration", "address_window", "soon"},
		{"wait duration", "wait_timeout", "soon"},
		{"negative wait", "wait_timeout", "-1s"},
		{"zero wait", "wait_timeout", "0s"},
		{"shutdown duration", "shutdown_timeout", "soon"},
		{"negative shutdown", "shutdown_timeout", "-1s"},
		{"zero shutdown", "shutdown_timeout", "0s"},
		{"negative duration", "decision_horizon", "-1s"},
		{"integer", "max_records", "many"},
		{"fractional integer", "max_candidates", 1.5},
		{"negative limit", "sdp_origin_max_tracked", -1},
		{"boolean", "sdp_origin_matching", "enabled"},
		{"alias JSON", "node_aliases", `[["192.0.2.1"]`},
		{"flat aliases", "node_aliases", []string{"192.0.2.1", "192.0.2.2"}},
		{"alias address", "node_aliases", [][]string{{"invalid", "192.0.2.1"}}},
		{"header name", "session_headers", []string{"Bad:Header"}},
		{"header value type", "parent_call_id_headers", []int{1}},
		{"store type", "store_file", true},
		{"missing store key", "store_file", "/protected/store"},
		{"malformed read key", "store_read_keys", []string{"bad"}},
		{"read key types", "store_read_keys", []int{1}},
		{"read key bound", "store_read_keys", []string{"a=/a", "b=/b", "c=/c", "d=/d", "e=/e"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetLICorrelationViper(t)
			viper.Set("processor.li.correlation."+test.key, test.value)
			_, err := readLICallCorrelationConfig()
			require.Error(t, err)
			var runtime processor.Config
			require.Error(t, applyLICallCorrelationConfig(&runtime), "parse failures must reject startup")
		})
	}
	t.Run("SDP TTL", func(t *testing.T) {
		resetLICorrelationViper(t)
		viper.Set("processor.li.correlation.sdp_origin_matching", true)
		viper.Set("processor.li.correlation.sdp_origin_observation_ttl", "30s")
		_, err := readLICallCorrelationConfig()
		require.Error(t, err)
	})
}

func TestLICallCorrelationRejectsMalformedEnvironment(t *testing.T) {
	resetLICorrelationViper(t)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_NUMBER_WINDOW", "not-a-duration")
	_, err := readLICallCorrelationConfig()
	require.ErrorContains(t, err, "number_window")
}

func TestLICallCorrelationRejectsDuplicateStoreKeyIDs(t *testing.T) {
	for _, prior := range [][]string{{"active=/old"}, {"old=/old", "old=/other"}} {
		t.Run(strings.Join(prior, ","), func(t *testing.T) {
			resetLICorrelationViper(t)
			viper.Set("processor.li.correlation.store_file", "/protected/store")
			viper.Set("processor.li.correlation.store_key_id", "active")
			viper.Set("processor.li.correlation.store_key_file", "/protected/active.key")
			viper.Set("processor.li.correlation.store_read_keys", prior)
			_, err := readLICallCorrelationConfig()
			require.ErrorContains(t, err, "unique IDs")
		})
	}
}

func TestLICallCorrelationIdentityProfilesAndResponseWait(t *testing.T) {
	resetLICorrelationViper(t)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`processor:
  li:
    correlation:
      response_wait: true
      response_wait_window: 12ms
      max_pending_dialogs: 20
      max_pending_packets: 50
      max_pending_bytes: 8192
      identity_profiles:
        - name: example
          namespace: tenant
          sip_hosts: [sip.example]
          phone_contexts: [local.example]
          global_tel: true
          allow_numeric_sip: true
          allow_bare_global: true
          international_prefixes: ['00']
          rewrite_rules:
            - pattern: '^99([0-9]+)$'
              replacement: '${1}'
`)))
	c, err := readLICallCorrelationConfig()
	require.NoError(t, err)
	require.True(t, c.ResponseWait)
	require.Equal(t, 12*time.Millisecond, c.ResponseWaitWindow)
	require.Equal(t, 20, c.MaxPendingDialogs)
	require.Equal(t, 50, c.MaxPendingPackets)
	require.Equal(t, 8192, c.MaxPendingBytes)
	require.False(t, c.Enabled())
	require.Equal(t, []li.CorrelationIdentityProfile{{Name: "example", Namespace: "tenant", SIPHosts: []string{"sip.example"}, PhoneContexts: []string{"local.example"}, GlobalTEL: true, AllowNumericSIP: true, AllowBareGlobal: true, InternationalPrefixes: []string{"00"}, RewriteRules: []li.CorrelationIdentityRewrite{{Pattern: `^99([0-9]+)$`, Replacement: `${1}`}}}}, c.IdentityProfiles)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_IDENTITY_PROFILES", `[{"name":"other","namespace":"tenant","sip_hosts":["other.example"]}]`)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_RESPONSE_WAIT", "false")
	c, err = readLICallCorrelationConfig()
	require.NoError(t, err)
	require.False(t, c.ResponseWait)
	require.Equal(t, "other", c.IdentityProfiles[0].Name)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_IDENTITY_PROFILES", "")
	c, err = readLICallCorrelationConfig()
	require.NoError(t, err)
	require.Empty(t, c.IdentityProfiles)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_CORRELATION_IDENTITY_PROFILES", `[]`)
	c, err = readLICallCorrelationConfig()
	require.NoError(t, err)
	require.Empty(t, c.IdentityProfiles)
}
func TestLICallCorrelationInvalidProfilesAndResponseBounds(t *testing.T) {
	for _, test := range []struct {
		key   string
		value any
	}{
		{"identity_profiles", `[{"name":"example","namespace":"example","sip_hosts":["sip.example"],"unknown":true}]`},
		{"identity_profiles", `[{"name":"example","namespace":"example","sip_hosts":["sip.example"],"allow_bare_global":"yes"}]`},
		{"identity_profiles", `[{"name":"example","namespace":"example","sip_hosts":["sip.example"],"rewrite_rules":[{"pattern":"unanchored","replacement":"x"}]}]`},
		{"response_wait_window", "-1ms"}, {"max_pending_dialogs", -1}, {"max_pending_packets", 1000001}, {"max_pending_bytes", -1},
	} {
		t.Run(test.key, func(t *testing.T) {
			resetLICorrelationViper(t)
			viper.Set("processor.li.correlation."+test.key, test.value)
			_, err := readLICallCorrelationConfig()
			require.ErrorContains(t, err, "processor.li.correlation")
		})
	}
}
