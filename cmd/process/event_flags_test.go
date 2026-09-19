//go:build processor || all

package process

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestEventAuthorizationFlagsAreBound(t *testing.T) {
	testEventAuthorizationFlagBinding(t, "event-allow-sensitive-fields", "processor.events.allow_sensitive_fields")
	testEventAuthorizationFlagBinding(t, "event-allow-file-metadata", "processor.events.allow_file_metadata")
}

func TestUpstreamEventForwardingFlagsAreBound(t *testing.T) {
	tests := []struct {
		flag, key, defaultValue, testValue string
	}{
		{flag: "forward-mode", key: "processor.forward_mode", defaultValue: "packets", testValue: "events"},
		{flag: "event-fallback-to-packets", key: "processor.events.fallback_to_packets", defaultValue: "false", testValue: "true"},
		{flag: "event-delivery-profile", key: "processor.events.delivery_profile", defaultValue: "reliable", testValue: "memory-only"},
		{flag: "event-spool-dir", key: "processor.events.spool.dir", defaultValue: "/var/tmp/lippycat-processor-event-spool", testValue: "/tmp/process-event-spool"},
		{flag: "event-spool-max-bytes", key: "processor.events.spool.max_bytes", defaultValue: "1073741824", testValue: "1234"},
		{flag: "event-spool-max-age", key: "processor.events.spool.max_age", defaultValue: "24h0m0s", testValue: "1m0s"},
		{flag: "event-spool-exhaustion-policy", key: "processor.events.spool.exhaustion_policy", defaultValue: "drop_oldest", testValue: "drop_new"},
	}
	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			flag := ProcessCmd.Flags().Lookup(tt.flag)
			require.NotNil(t, flag)
			require.Equal(t, tt.defaultValue, flag.DefValue)
			previous := flag.Value.String()
			t.Cleanup(func() {
				require.NoError(t, flag.Value.Set(previous))
				flag.Changed = false
			})
			require.NoError(t, flag.Value.Set(tt.testValue))
			flag.Changed = true
			require.Equal(t, tt.testValue, viper.GetString(tt.key), "flag must be bound to %s", tt.key)
		})
	}
}

func TestApplyProcessEventTransportConfig(t *testing.T) {
	oldMode, oldFallback := forwardMode, eventFallbackToPackets
	oldDelivery, oldDir := eventDeliveryProfile, eventSpoolDir
	oldBytes, oldAge, oldPolicy := eventSpoolMaxBytes, eventSpoolMaxAge, eventSpoolExhaustionPolicy
	t.Cleanup(func() {
		forwardMode, eventFallbackToPackets = oldMode, oldFallback
		eventDeliveryProfile, eventSpoolDir = oldDelivery, oldDir
		eventSpoolMaxBytes, eventSpoolMaxAge, eventSpoolExhaustionPolicy = oldBytes, oldAge, oldPolicy
	})
	forwardMode, eventFallbackToPackets = "events", true
	eventDeliveryProfile, eventSpoolDir = "memory-only", "/tmp/process-event-spool"
	eventSpoolMaxBytes, eventSpoolMaxAge, eventSpoolExhaustionPolicy = 1234, time.Minute, "drop_new"

	config := processor.Config{}
	require.NoError(t, applyProcessEventTransportConfig(&config))
	require.Equal(t, "events", config.UpstreamForwardMode)
	require.True(t, config.UpstreamEventFallbackToPackets)
	require.Equal(t, "memory_only", config.UpstreamEventDeliveryProfile)
	require.Equal(t, "/tmp/process-event-spool", config.UpstreamEventSpoolDirectory)
	require.Equal(t, uint64(1234), config.UpstreamEventSpoolMaxBytes)
	require.Equal(t, time.Minute, config.UpstreamEventSpoolMaxAge)
	require.Equal(t, "drop_new", config.UpstreamEventSpoolExhaustionPolicy)
}

func TestProcessEventTransportConfigHonorsYAMLAndFlagPrecedence(t *testing.T) {
	flagNames := []string{"forward-mode", "event-fallback-to-packets", "event-delivery-profile", "event-spool-dir", "event-spool-max-bytes", "event-spool-max-age", "event-spool-exhaustion-policy"}
	type flagState struct {
		value   string
		changed bool
	}
	states := make(map[string]flagState, len(flagNames))
	for _, name := range flagNames {
		flag := ProcessCmd.Flags().Lookup(name)
		states[name] = flagState{value: flag.Value.String(), changed: flag.Changed}
		require.NoError(t, flag.Value.Set(flag.DefValue))
		flag.Changed = false
	}
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`
processor:
  forward_mode: events
  events:
    fallback_to_packets: false
    delivery_profile: memory-only
    spool:
      dir: /yaml/process-spool
      max_bytes: 4321
      max_age: 2m
      exhaustion_policy: drop_new
`)))
	t.Cleanup(func() {
		for name, state := range states {
			flag := ProcessCmd.Flags().Lookup(name)
			require.NoError(t, flag.Value.Set(state.value))
			flag.Changed = state.changed
		}
		require.NoError(t, viper.ReadConfig(strings.NewReader("{}")))
	})

	config := processor.Config{}
	require.NoError(t, applyProcessEventTransportConfig(&config))
	require.Equal(t, "events", config.UpstreamForwardMode)
	require.Equal(t, "memory_only", config.UpstreamEventDeliveryProfile)
	require.Equal(t, "/yaml/process-spool", config.UpstreamEventSpoolDirectory)
	require.Equal(t, uint64(4321), config.UpstreamEventSpoolMaxBytes)
	require.Equal(t, 2*time.Minute, config.UpstreamEventSpoolMaxAge)
	require.Equal(t, "drop_new", config.UpstreamEventSpoolExhaustionPolicy)

	modeFlag := ProcessCmd.Flags().Lookup("forward-mode")
	require.NoError(t, modeFlag.Value.Set("packets"))
	modeFlag.Changed = true
	require.NoError(t, applyProcessEventTransportConfig(&config))
	require.Equal(t, "packets", config.UpstreamForwardMode)
}

func TestValidateProcessEventTransportConfig(t *testing.T) {
	valid := processor.Config{
		UpstreamForwardMode:                "events",
		UpstreamEventDeliveryProfile:       "reliable",
		UpstreamEventSpoolDirectory:        "/tmp/process-event-spool",
		UpstreamEventSpoolExhaustionPolicy: "drop_oldest",
	}
	tests := []struct {
		name, want string
		mutate     func(*processor.Config)
	}{
		{name: "mode", want: "invalid forward mode", mutate: func(c *processor.Config) { c.UpstreamForwardMode = "invalid" }},
		{name: "profile", want: "invalid event delivery profile", mutate: func(c *processor.Config) { c.UpstreamEventDeliveryProfile = "invalid" }},
		{name: "fallback", want: "only valid with --forward-mode=events", mutate: func(c *processor.Config) { c.UpstreamForwardMode = "packets"; c.UpstreamEventFallbackToPackets = true }},
		{name: "policy", want: "invalid event spool exhaustion policy", mutate: func(c *processor.Config) { c.UpstreamEventSpoolExhaustionPolicy = "invalid" }},
		{name: "reliable spool", want: "non-empty event spool directory", mutate: func(c *processor.Config) { c.UpstreamEventSpoolDirectory = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := valid
			tt.mutate(&config)
			require.ErrorContains(t, validateProcessEventTransportConfig(config), tt.want)
		})
	}
}

func testEventAuthorizationFlagBinding(t *testing.T, flagName, key string) {
	t.Helper()
	flag := ProcessCmd.Flags().Lookup(flagName)
	require.NotNil(t, flag)
	previous := flag.Value.String()
	t.Cleanup(func() {
		require.NoError(t, flag.Value.Set(previous))
		flag.Changed = false
	})

	viper.SetDefault(key, false)
	require.NoError(t, flag.Value.Set("true"))
	flag.Changed = true
	require.True(t, viper.GetBool(key))
}
