//go:build hunter || all

package hunt

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildHunterConfigProtocolFixtures(t *testing.T) {
	processorAddr = "processor.example:55555"
	hunterID = "edge-01"
	interfaces = []string{"eth0", "eth1"}
	bufferSize = 1234
	sipBufferSize = 321
	batchSize = 42
	batchTimeout = 75
	batchQueueSize = 91
	insecureAllowed = false
	tlsCertFile = "client.crt"
	tlsKeyFile = "client.key"
	tlsCAFile = "ca.crt"
	tlsSkipVerify = false
	noFilterPolicy = "deny"
	diskBufferEnabled = true
	diskBufferDir = "/var/tmp/lippycat-test-buffer"
	diskBufferMaxSize = 17

	tests := []struct {
		name               string
		wantVoIP           bool
		wantVoIPFilter     bool
		wantFilterTypes    []string
		wantDiskBuffer     bool
		wantNoFilterPolicy string
	}{
		{name: "dns", wantFilterTypes: []string{"bpf", "ip_address", "dns_domain"}},
		{name: "http", wantFilterTypes: []string{"bpf", "ip_address", "http_host", "http_path"}},
		{name: "tls", wantFilterTypes: []string{"bpf", "ip_address", "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4"}},
		{name: "email", wantFilterTypes: []string{"bpf", "ip_address", "email_address", "email_subject"}},
		{name: "voip", wantVoIP: true, wantVoIPFilter: true, wantNoFilterPolicy: "deny"},
		{name: "generic", wantDiskBuffer: true, wantNoFilterPolicy: "deny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filterFixture := tt.name + "-filter"
			var spec hunterConfigSpec
			if tt.name == "generic" {
				spec = genericHunterConfigSpec(filterFixture)
			} else {
				spec = protocolHunterConfigSpec(tt.name, filterFixture)
			}
			if tt.name != "generic" {
				assert.Equal(t, protocolcatalog.MustLookup(tt.name), spec.protocol)
			}
			config := buildHunterConfig(spec)
			require.Equal(t, "processor.example:55555", config.ProcessorAddr)
			assert.Equal(t, "edge-01", config.HunterID)
			assert.Equal(t, []string{"eth0", "eth1"}, config.Interfaces)
			assert.Equal(t, filterFixture, config.BPFFilter)
			assert.Equal(t, 1234, config.BufferSize)
			assert.Equal(t, 321, config.SIPBufferSize)
			assert.Equal(t, 42, config.BatchSize)
			assert.Equal(t, 75*time.Millisecond, config.BatchTimeout)
			assert.Equal(t, 91, config.BatchQueueSize)
			assert.Equal(t, tt.wantVoIP, config.VoIPMode)
			assert.Equal(t, tt.wantVoIPFilter, config.EnableVoIPFilter)
			assert.Equal(t, tt.wantFilterTypes, config.SupportedFilterTypes)
			assert.True(t, config.TLSEnabled)
			assert.Equal(t, "client.crt", config.TLSCertFile)
			assert.Equal(t, "client.key", config.TLSKeyFile)
			assert.Equal(t, "ca.crt", config.TLSCAFile)
			assert.Equal(t, tt.wantDiskBuffer, config.DiskBufferEnabled)
			assert.Equal(t, tt.wantNoFilterPolicy, config.NoFilterPolicy)
			if tt.wantDiskBuffer {
				assert.Equal(t, "/var/tmp/lippycat-test-buffer", config.DiskBufferDir)
				assert.Equal(t, uint64(17*1024*1024), config.DiskBufferMaxSize)
			}
		})
	}
}

func TestHunterEventTransportConfigHonorsYAMLAndFlagPrecedence(t *testing.T) {
	flagNames := []string{"forward-mode", "event-fallback-to-packets", "event-delivery-profile", "event-spool-dir", "event-spool-max-bytes", "event-spool-max-age", "event-spool-exhaustion-policy"}
	type flagState struct {
		value   string
		changed bool
	}
	states := make(map[string]flagState, len(flagNames))
	for _, name := range flagNames {
		flag := HuntCmd.PersistentFlags().Lookup(name)
		states[name] = flagState{value: flag.Value.String(), changed: flag.Changed}
		require.NoError(t, flag.Value.Set(flag.DefValue))
		flag.Changed = false
	}
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`
hunter:
  forward_mode: events
  events:
    fallback_to_packets: false
    delivery_profile: memory-only
    spool:
      dir: /yaml/hunter-spool
      max_bytes: 4321
      max_age: 2m
      exhaustion_policy: drop_new
`)))
	t.Cleanup(func() {
		for name, state := range states {
			flag := HuntCmd.PersistentFlags().Lookup(name)
			require.NoError(t, flag.Value.Set(state.value))
			flag.Changed = state.changed
		}
		require.NoError(t, viper.ReadConfig(strings.NewReader("{}")))
	})

	config := buildHunterConfig(hunterConfigSpec{})
	require.NoError(t, validateHunterForwardingConfig(config))
	require.Equal(t, "events", config.ForwardMode)
	require.Equal(t, "memory_only", config.EventDeliveryProfile)
	require.Equal(t, "/yaml/hunter-spool", config.EventSpoolDir)
	require.Equal(t, uint64(4321), config.EventSpoolMaxBytes)
	require.Equal(t, 2*time.Minute, config.EventSpoolMaxAge)
	require.Equal(t, "drop_new", config.EventSpoolExhaustionPolicy)

	modeFlag := HuntCmd.PersistentFlags().Lookup("forward-mode")
	require.NoError(t, modeFlag.Value.Set("packets"))
	modeFlag.Changed = true
	config = buildHunterConfig(hunterConfigSpec{})
	require.NoError(t, validateHunterForwardingConfig(config))
	require.Equal(t, "packets", config.ForwardMode)
}

func TestBuildHunterConfigCopiesFilterCapabilities(t *testing.T) {
	filterTypes := []string{"bpf", "dns_domain"}
	config := buildHunterConfig(hunterConfigSpec{protocol: protocolcatalog.Spec{SupportedFilterTypes: filterTypes}})
	filterTypes[1] = "changed"
	assert.Equal(t, []string{"bpf", "dns_domain"}, config.SupportedFilterTypes)
}

func TestValidateHunterForwardingConfig(t *testing.T) {
	valid := hunter.Config{ForwardMode: "events", EventDeliveryProfile: "reliable", EventSpoolDir: "/tmp/spool", EventSpoolExhaustionPolicy: "drop_oldest"}
	require.NoError(t, validateHunterForwardingConfig(valid))

	tests := []struct {
		name   string
		mutate func(*hunter.Config)
	}{
		{name: "invalid mode", mutate: func(c *hunter.Config) { c.ForwardMode = "auto" }},
		{name: "implicit fallback", mutate: func(c *hunter.Config) { c.ForwardMode = "packets"; c.EventFallbackToPackets = true }},
		{name: "missing reliable spool", mutate: func(c *hunter.Config) { c.EventSpoolDir = "" }},
		{name: "invalid exhaustion policy", mutate: func(c *hunter.Config) { c.EventSpoolExhaustionPolicy = "overwrite" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := valid
			tt.mutate(&config)
			require.Error(t, validateHunterForwardingConfig(config))
		})
	}
}

func TestHunterSIPBufferConfigPrecedence(t *testing.T) {
	flag := HuntCmd.PersistentFlags().Lookup("sip-buffer-size")
	require.NotNil(t, flag)
	originalValue, originalChanged := flag.Value.String(), flag.Changed
	originalEnv, hadEnv := os.LookupEnv("LIPPYCAT_HUNTER_SIP_BUFFER_SIZE")
	t.Cleanup(func() {
		require.NoError(t, flag.Value.Set(originalValue))
		flag.Changed = originalChanged
		require.NoError(t, viper.ReadConfig(strings.NewReader("{}")))
		if hadEnv {
			require.NoError(t, os.Setenv("LIPPYCAT_HUNTER_SIP_BUFFER_SIZE", originalEnv))
		} else {
			require.NoError(t, os.Unsetenv("LIPPYCAT_HUNTER_SIP_BUFFER_SIZE"))
		}
	})

	require.NoError(t, flag.Value.Set(flag.DefValue))
	flag.Changed = false
	require.NoError(t, os.Unsetenv("LIPPYCAT_HUNTER_SIP_BUFFER_SIZE"))
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader("hunter:\n  sip_buffer_size: 23\n")))
	require.Equal(t, 23, buildHunterConfig(hunterConfigSpec{}).SIPBufferSize)

	require.NoError(t, os.Setenv("LIPPYCAT_HUNTER_SIP_BUFFER_SIZE", "37"))
	require.Equal(t, 37, buildHunterConfig(hunterConfigSpec{}).SIPBufferSize)

	require.NoError(t, flag.Value.Set("0"))
	flag.Changed = true
	zeroConfig, err := buildHunterConfigChecked(hunterConfigSpec{})
	require.NoError(t, err)
	require.Zero(t, zeroConfig.SIPBufferSize, "an explicit CLI zero must override config and environment values")

	require.NoError(t, flag.Value.Set("41"))
	flag.Changed = true
	require.Equal(t, 41, buildHunterConfig(hunterConfigSpec{}).SIPBufferSize)
}

func TestValidateHunterSIPBufferSize(t *testing.T) {
	err := validateHunterForwardingConfig(hunter.Config{SIPBufferSize: -1})
	require.ErrorContains(t, err, "hunter.sip_buffer_size")
}

func TestBuildHunterConfigRejectsMalformedSIPBufferSize(t *testing.T) {
	original := viper.Get("hunter.sip_buffer_size")
	t.Cleanup(func() { viper.Set("hunter.sip_buffer_size", original) })

	viper.Set("hunter.sip_buffer_size", "not-a-number")
	_, err := buildHunterConfigChecked(hunterConfigSpec{})
	require.ErrorContains(t, err, "hunter.sip_buffer_size")
}
