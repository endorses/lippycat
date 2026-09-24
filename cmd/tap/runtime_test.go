//go:build tap || all

package tap

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"

	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTapSourceConfigUsesSharedProtocol(t *testing.T) {
	oldInterfaces, oldBatchSize, oldBatchTimeout, oldBufferSize, oldSIPBufferSize := interfaces, batchSize, batchTimeout, bufferSize, sipBufferSize
	t.Cleanup(func() {
		interfaces, batchSize, batchTimeout, bufferSize, sipBufferSize = oldInterfaces, oldBatchSize, oldBatchTimeout, oldBufferSize, oldSIPBufferSize
	})
	interfaces = []string{"eth0", "eth1"}
	batchSize, batchTimeout, bufferSize = 42, 250, 2048
	sipBufferSize = 512

	got := tapSourceConfig(processor.Config{
		ProcessorID: "tap-test",
		LogConfig:   &processor.StructuredLogConfig{IncludeHTTPHeaders: true},
	}, "tcp port 443", protocolcatalog.MustLookup("tls"))
	require.Equal(t, []string{"eth0", "eth1"}, got.Interfaces)
	require.Equal(t, "tcp port 443", got.BPFFilter)
	require.Equal(t, 42, got.BatchSize)
	require.Equal(t, 250*time.Millisecond, got.BatchTimeout)
	require.Equal(t, 2048, got.BufferSize)
	require.Equal(t, 512, got.SIPBufferSize)
	require.Equal(t, 1000, got.BatchBuffer)
	require.Equal(t, "tap-test", got.ProcessorID)
	require.Equal(t, "tls", got.ProtocolMode)
	require.True(t, got.IncludeHTTPHeaders)
}

func TestTapSourceConfigSupportsGenericMode(t *testing.T) {
	got := tapSourceConfig(processor.Config{ProcessorID: "generic-tap"}, "udp", protocolcatalog.MustLookup("generic"))

	require.Equal(t, "generic-tap", got.ProcessorID)
	require.Equal(t, "generic", got.ProtocolMode)
	require.Equal(t, "udp", got.BPFFilter)
	require.False(t, got.IncludeHTTPHeaders)
}

func TestTapSIPBufferConfigPrecedence(t *testing.T) {
	flag := TapCmd.PersistentFlags().Lookup("sip-buffer-size")
	require.NotNil(t, flag)
	originalValue, originalChanged := flag.Value.String(), flag.Changed
	originalEnv, hadEnv := os.LookupEnv("LIPPYCAT_TAP_SIP_BUFFER_SIZE")
	oldSIPBufferSize := sipBufferSize
	t.Cleanup(func() {
		require.NoError(t, flag.Value.Set(originalValue))
		flag.Changed = originalChanged
		sipBufferSize = oldSIPBufferSize
		require.NoError(t, viper.ReadConfig(strings.NewReader("{}")))
		if hadEnv {
			require.NoError(t, os.Setenv("LIPPYCAT_TAP_SIP_BUFFER_SIZE", originalEnv))
		} else {
			require.NoError(t, os.Unsetenv("LIPPYCAT_TAP_SIP_BUFFER_SIZE"))
		}
	})

	require.Equal(t, "0", flag.DefValue)
	require.NoError(t, flag.Value.Set(flag.DefValue))
	flag.Changed = false
	sipBufferSize = 0
	require.NoError(t, os.Unsetenv("LIPPYCAT_TAP_SIP_BUFFER_SIZE"))
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader("tap:\n  sip_buffer_size: 29\n")))
	require.Equal(t, 29, tapSourceConfig(processor.Config{}, "", protocolcatalog.MustLookup("generic")).SIPBufferSize)

	require.NoError(t, os.Setenv("LIPPYCAT_TAP_SIP_BUFFER_SIZE", "43"))
	require.Equal(t, 43, tapSourceConfig(processor.Config{}, "", protocolcatalog.MustLookup("generic")).SIPBufferSize)

	require.NoError(t, flag.Value.Set("0"))
	flag.Changed = true
	zeroConfig, err := tapSourceConfigChecked(processor.Config{}, "", protocolcatalog.MustLookup("generic"))
	require.NoError(t, err)
	require.Zero(t, zeroConfig.SIPBufferSize, "an explicit CLI zero must override config and environment values")

	require.NoError(t, flag.Value.Set("47"))
	flag.Changed = true
	require.Equal(t, 47, tapSourceConfig(processor.Config{}, "", protocolcatalog.MustLookup("generic")).SIPBufferSize)
}

func TestTapRejectsNegativeSIPBufferSize(t *testing.T) {
	oldSIPBufferSize := sipBufferSize
	sipBufferSize = -1
	t.Cleanup(func() { sipBufferSize = oldSIPBufferSize })

	_, err := newTapRuntime(processor.Config{}, "", protocolcatalog.MustLookup("generic"), tapRuntimeHooks{})
	require.ErrorContains(t, err, "tap.sip_buffer_size")
}

func TestTapRejectsMalformedSIPBufferSize(t *testing.T) {
	original := viper.Get("tap.sip_buffer_size")
	t.Cleanup(func() { viper.Set("tap.sip_buffer_size", original) })

	viper.Set("tap.sip_buffer_size", "not-a-number")
	_, err := newTapRuntime(processor.Config{}, "", protocolcatalog.MustLookup("generic"), tapRuntimeHooks{})
	require.ErrorContains(t, err, "tap.sip_buffer_size")
}

func TestTapProtocolsComeFromSharedCatalog(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"dns", "email", "generic", "http", "tls", "voip"} {
		protocol := protocolcatalog.MustLookup(name)
		require.Equal(t, name, protocol.Name)
	}
}

type tapProtocolContract struct {
	cmd      *cobra.Command
	short    string
	flags    map[string]string
	bindings map[string]string
	helpHash string
}

func TestTapProtocolCLIContracts(t *testing.T) {
	contracts := map[string]tapProtocolContract{
		"dns": {
			cmd: dnsTapCmd, short: "Standalone DNS capture with full processor capabilities",
			helpHash: "61f8d02dec22488bd00774c52a8168ef5e89c303ec703fad49e212068f07e63b",
			flags:    tapFlagDefaults("detect-tunneling", "true", "dns-port", "53", "domain", "", "domains-file", "", "tunneling-command", "", "tunneling-debounce", "5m", "tunneling-threshold", "0.7", "udp-only", "false"),
			bindings: tapBindings("detect-tunneling", "dns.detect_tunneling", "dns-port", "tap.dns.ports", "domain", "tap.dns.domain_pattern", "domains-file", "tap.dns.domains_file", "tunneling-command", "processor.tunneling_command", "tunneling-debounce", "processor.tunneling_debounce", "tunneling-threshold", "processor.tunneling_threshold", "udp-only", "tap.dns.udp_only"),
		},
		"http": {
			cmd: httpTapCmd, short: "Standalone HTTP capture with full processor capabilities",
			helpHash: "d85bfee9b715678534cf697bad2d06cfed5900aa37c6eacaef22656a5c928a0e",
			flags:    tapFlagDefaults("capture-body", "false", "content-type", "", "content-types-file", "", "host", "", "hosts-file", "", "http-port", "80,8080,8000,3000,8888", "keywords-file", "", "max-body-size", "65536", "method", "", "path", "", "paths-file", "", "status", "", "tls-keylog", "", "tls-keylog-pipe", "", "user-agent", "", "user-agents-file", ""),
			bindings: tapBindings("capture-body", "tap.http.capture_body", "content-type", "tap.http.content_type_pattern", "content-types-file", "tap.http.content_types_file", "host", "tap.http.host_pattern", "hosts-file", "tap.http.hosts_file", "http-port", "tap.http.ports", "keywords-file", "tap.http.keywords_file", "max-body-size", "tap.http.max_body_size", "method", "tap.http.methods", "path", "tap.http.path_pattern", "paths-file", "tap.http.paths_file", "status", "tap.http.status_codes", "tls-keylog", "tap.http.tls_keylog", "tls-keylog-pipe", "tap.http.tls_keylog_pipe", "user-agent", "tap.http.user_agent_pattern", "user-agents-file", "tap.http.user_agents_file"),
		},
		"tls": {
			cmd: tlsTapCmd, short: "Standalone TLS capture with full processor capabilities",
			helpHash: "adb79cdc644a5b224bef9326967bc910a12012d1d0dca8a27e0acd847ba91523",
			flags:    tapFlagDefaults("sni", "", "sni-file", "", "tls-port", "443"),
			bindings: tapBindings("sni", "tap.tls.sni_pattern", "sni-file", "tap.tls.sni_file", "tls-port", "tap.tls.ports"),
		},
		"email": {
			cmd: emailTapCmd, short: "Standalone email capture with full processor capabilities",
			helpHash: "99b3339e2d72143172c90119d176af94ab1845a50958660e6aaa376f35046a5a",
			flags:    tapFlagDefaults("address", "", "addresses-file", "", "capture-body", "false", "command", "", "imap-port", "143,993", "keywords-file", "", "mailbox", "", "max-body-size", "65536", "pop3-port", "110,995", "protocol", "all", "recipient", "", "recipients-file", "", "sender", "", "senders-file", "", "smtp-port", "25,587,465", "subject", "", "subjects-file", ""),
			bindings: tapBindings("address", "tap.email.address_pattern", "addresses-file", "tap.email.addresses_file", "capture-body", "tap.email.capture_body", "command", "tap.email.command_pattern", "imap-port", "tap.email.imap_ports", "keywords-file", "tap.email.keywords_file", "mailbox", "tap.email.mailbox_pattern", "max-body-size", "tap.email.max_body_size", "pop3-port", "tap.email.pop3_ports", "protocol", "tap.email.protocol", "recipient", "tap.email.recipient_pattern", "recipients-file", "tap.email.recipients_file", "sender", "tap.email.sender_pattern", "senders-file", "tap.email.senders_file", "smtp-port", "tap.email.smtp_ports", "subject", "tap.email.subject_pattern", "subjects-file", "tap.email.subjects_file"),
		},
		"voip": {
			cmd: voipTapCmd, short: "Standalone VoIP capture with full processor capabilities",
			helpHash: "728f7be7c2caa156c31aed1be91de02ea594dea54b5ef491bacba32e33246205",
			flags:    tapFlagDefaults("pattern-algorithm", "auto", "pattern-buffer-mb", "64", "pcap-closed-call-ttl", "1h0m0s", "pcap-grace-period", "5s", "per-call-pcap", "false", "per-call-pcap-dir", "./pcaps", "per-call-pcap-max-idle", "10m0s", "per-call-pcap-max-writers", "0", "per-call-pcap-pattern", "{timestamp}_{callid}.pcap", "rtp-port-range", "", "sip-port", "", "sip-retry-window", "2m0s", "sip-user", "", "sipuser", "", "tcp-performance-mode", "balanced", "tcp-reassembly-shards", "1", "tcp-sip-idle-timeout", "0s", "udp-only", "false"),
			bindings: tapBindings("pattern-algorithm", "tap.voip.pattern_algorithm", "pattern-buffer-mb", "tap.voip.pattern_buffer_mb", "pcap-closed-call-ttl", "tap.per_call_pcap.closed_call_ttl", "pcap-grace-period", "tap.per_call_pcap.grace_period", "per-call-pcap", "tap.per_call_pcap.enabled", "per-call-pcap-dir", "tap.per_call_pcap.output_dir", "per-call-pcap-max-idle", "tap.per_call_pcap.max_idle", "per-call-pcap-max-writers", "tap.per_call_pcap.max_writers", "per-call-pcap-pattern", "tap.per_call_pcap.file_pattern", "rtp-port-range", "tap.voip.rtp_port_ranges", "sip-port", "tap.voip.sip_ports", "sip-retry-window", "tap.voip.sip_retry_window", "sip-user", "tap.voip.sip_user", "tcp-performance-mode", "tap.voip.tcp_performance_mode", "tcp-reassembly-shards", "tap.voip.tcp_reassembly_shards", "tcp-sip-idle-timeout", "voip.tcp_sip_idle_timeout", "udp-only", "tap.voip.udp_only"),
		},
	}

	// LI builds include inherited delivery flags in protocol help. Keep separate
	// complete-help snapshots so non-LI help remains an independent contract.
	if TapCmd.PersistentFlags().Lookup("li-enabled") != nil {
		liHashes := map[string]string{
			"dns":   "8bc9aa3a3f75001bc956e5cc190752d636e6e49c48f5b38debf2cc9b1e1c0269",
			"http":  "d73743cab549fa32d39dd71615fd874f8ba133e41ef5b6d5219f3fb99f7b50de",
			"tls":   "4a1939e1c2ed44a54c3299b79bce3073dbd069723573068a5c8cae9c475639e6",
			"email": "d4e293b3af30734af6c1fbb9f511d87d0d7384b50d61af429753e1c7584ce274",
			"voip":  "cee990b15be1d009607054125883d386a4bf5a45249ab7cf59981a25ae1d8836",
		}
		for name, hash := range liHashes {
			contract := contracts[name]
			contract.helpHash = hash
			contracts[name] = contract
		}
	}

	for name, contract := range contracts {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, name, contract.cmd.Use)
			require.Equal(t, contract.short, contract.cmd.Short)
			require.Equal(t, contract.helpHash, tapHelpHash(t, contract.cmd))
			require.Equal(t, contract.flags, tapCommandFlagDefaults(contract.cmd))
			for flagName, key := range contract.bindings {
				assertTapViperBinding(t, contract.cmd, flagName, key)
			}
		})
	}
}

func tapHelpHash(t *testing.T, cmd *cobra.Command) string {
	t.Helper()
	var output bytes.Buffer
	originalOut := cmd.OutOrStdout()
	cmd.SetOut(&output)
	t.Cleanup(func() { cmd.SetOut(originalOut) })
	cmd.HelpFunc()(cmd, nil)
	return fmt.Sprintf("%x", sha256.Sum256(output.Bytes()))
}

func assertTapViperBinding(t *testing.T, cmd *cobra.Command, flagName, key string) {
	t.Helper()
	flag := cmd.Flags().Lookup(flagName)
	require.NotNil(t, flag, "binding references missing flag")

	original, originalChanged := flag.Value.String(), flag.Changed
	sentinel := "phase7-binding"
	switch flag.Value.Type() {
	case "bool":
		if original == "true" {
			sentinel = "false"
		} else {
			sentinel = "true"
		}
	case "float64":
		sentinel = "0.314159"
	case "int":
		sentinel = "314159"
	case "duration":
		sentinel = "3m14s"
	}
	require.NoError(t, flag.Value.Set(sentinel))
	flag.Changed = true
	t.Cleanup(func() {
		require.NoError(t, flag.Value.Set(original))
		flag.Changed = originalChanged
	})
	require.Equal(t, flag.Value.String(), fmt.Sprint(viper.Get(key)),
		"Viper key %q is not bound to --%s", key, flagName)
}

func tapCommandFlagDefaults(cmd *cobra.Command) map[string]string {
	result := make(map[string]string)
	cmd.LocalNonPersistentFlags().VisitAll(func(flag *pflag.Flag) { result[flag.Name] = flag.DefValue })
	return result
}

func tapFlagDefaults(values ...string) map[string]string { return tapPairs(values...) }
func tapBindings(values ...string) map[string]string     { return tapPairs(values...) }

func tapPairs(values ...string) map[string]string {
	if len(values)%2 != 0 {
		panic(fmt.Sprintf("odd contract pair count: %d", len(values)))
	}
	result := make(map[string]string, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		result[values[i]] = values[i+1]
	}
	return result
}

func TestTapProtocolContractNamesAreStable(t *testing.T) {
	names := []string{dnsTapCmd.Use, emailTapCmd.Use, httpTapCmd.Use, tlsTapCmd.Use, voipTapCmd.Use}
	sort.Strings(names)
	require.Equal(t, []string{"dns", "email", "http", "tls", "voip"}, names)
}

func TestApplyTapEventTransportConfig(t *testing.T) {
	oldForwardMode, oldFallback := forwardMode, eventFallbackToPackets
	oldDelivery, oldSpoolDir, oldPolicy := eventDeliveryProfile, eventSpoolDir, eventSpoolExhaustionPolicy
	oldIngress, oldWALDir := eventIngressProfile, eventIngressWALDir
	t.Cleanup(func() {
		forwardMode, eventFallbackToPackets = oldForwardMode, oldFallback
		eventDeliveryProfile, eventSpoolDir, eventSpoolExhaustionPolicy = oldDelivery, oldSpoolDir, oldPolicy
		eventIngressProfile, eventIngressWALDir = oldIngress, oldWALDir
	})
	forwardMode, eventFallbackToPackets = "events", false
	eventDeliveryProfile, eventSpoolDir, eventSpoolExhaustionPolicy = "memory-only", "/tmp/tap-spool", "drop_new"
	eventIngressProfile, eventIngressWALDir = "reliable", "/tmp/tap-wal"

	config := processor.Config{}
	require.NoError(t, applyTapEventTransportConfig(&config))
	require.Equal(t, "events", config.UpstreamForwardMode)
	require.Equal(t, "memory_only", config.UpstreamEventDeliveryProfile)
	require.Equal(t, "drop_new", config.UpstreamEventSpoolExhaustionPolicy)
	require.Equal(t, "reliable", config.EventIngressProfile)
	require.Equal(t, "/tmp/tap-wal", config.EventIngressWALDirectory)
}

func TestApplyTapEventTransportConfigRejectsImplicitFallback(t *testing.T) {
	oldMode, oldFallback := forwardMode, eventFallbackToPackets
	t.Cleanup(func() { forwardMode, eventFallbackToPackets = oldMode, oldFallback })
	forwardMode, eventFallbackToPackets = "packets", true

	err := applyTapEventTransportConfig(&processor.Config{})
	require.ErrorContains(t, err, "only valid with --forward-mode=events")
}

func TestApplyTapEventTransportConfigRejectsIngressBelowDurableContract(t *testing.T) {
	oldLimit := eventIngressMaxBatchBytes
	t.Cleanup(func() { eventIngressMaxBatchBytes = oldLimit })
	eventIngressMaxBatchBytes = protoadapter.MaxEncodedBatchBytes - 1

	err := applyTapEventTransportConfig(&processor.Config{})
	require.ErrorContains(t, err, "max batch bytes must be at least")
}

func TestTapEventTransportConfigHonorsYAMLAndFlagPrecedence(t *testing.T) {
	flagNames := []string{"forward-mode", "event-fallback-to-packets", "event-delivery-profile", "event-spool-dir", "event-spool-max-bytes", "event-spool-max-age", "event-spool-exhaustion-policy", "event-ingress-profile", "event-ingress-wal-dir", "event-ingress-wal-max-bytes", "event-ingress-max-batch-bytes"}
	type flagState struct {
		value   string
		changed bool
	}
	states := make(map[string]flagState, len(flagNames))
	for _, name := range flagNames {
		flag := TapCmd.PersistentFlags().Lookup(name)
		states[name] = flagState{value: flag.Value.String(), changed: flag.Changed}
		require.NoError(t, flag.Value.Set(flag.DefValue))
		flag.Changed = false
	}
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`
tap:
  forward_mode: events
  events:
    fallback_to_packets: false
    delivery_profile: memory-only
    spool:
      dir: /yaml/tap-spool
      max_bytes: 4321
      max_age: 2m
      exhaustion_policy: drop_new
    ingress:
      profile: reliable
      wal_dir: /yaml/tap-wal
      wal_max_bytes: 5678
      max_batch_bytes: 4194304
`)))
	t.Cleanup(func() {
		for name, state := range states {
			flag := TapCmd.PersistentFlags().Lookup(name)
			require.NoError(t, flag.Value.Set(state.value))
			flag.Changed = state.changed
		}
		require.NoError(t, viper.ReadConfig(strings.NewReader("{}")))
	})

	config := processor.Config{}
	require.NoError(t, applyTapEventTransportConfig(&config))
	require.Equal(t, "events", config.UpstreamForwardMode)
	require.Equal(t, "memory_only", config.UpstreamEventDeliveryProfile)
	require.Equal(t, "/yaml/tap-spool", config.UpstreamEventSpoolDirectory)
	require.Equal(t, uint64(4321), config.UpstreamEventSpoolMaxBytes)
	require.Equal(t, 2*time.Minute, config.UpstreamEventSpoolMaxAge)
	require.Equal(t, "drop_new", config.UpstreamEventSpoolExhaustionPolicy)
	require.Equal(t, "reliable", config.EventIngressProfile)
	require.Equal(t, "/yaml/tap-wal", config.EventIngressWALDirectory)

	modeFlag := TapCmd.PersistentFlags().Lookup("forward-mode")
	require.NoError(t, modeFlag.Value.Set("packets"))
	modeFlag.Changed = true
	require.NoError(t, applyTapEventTransportConfig(&config))
	require.Equal(t, "packets", config.UpstreamForwardMode)
}
