//go:build tap || all

package tap

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTapSourceConfigUsesSharedProtocol(t *testing.T) {
	oldInterfaces, oldBatchSize, oldBatchTimeout, oldBufferSize := interfaces, batchSize, batchTimeout, bufferSize
	t.Cleanup(func() {
		interfaces, batchSize, batchTimeout, bufferSize = oldInterfaces, oldBatchSize, oldBatchTimeout, oldBufferSize
	})
	interfaces = []string{"eth0", "eth1"}
	batchSize, batchTimeout, bufferSize = 42, 250, 2048

	got := tapSourceConfig(processor.Config{
		ProcessorID: "tap-test",
		LogConfig:   &processor.StructuredLogConfig{IncludeHTTPHeaders: true},
	}, "tcp port 443", protocolcatalog.MustLookup("tls"))
	require.Equal(t, []string{"eth0", "eth1"}, got.Interfaces)
	require.Equal(t, "tcp port 443", got.BPFFilter)
	require.Equal(t, 42, got.BatchSize)
	require.Equal(t, 250*time.Millisecond, got.BatchTimeout)
	require.Equal(t, 2048, got.BufferSize)
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
			helpHash: "bd942944d76146cf872de9f30c7755bfb21a7f20da0a0267d1276fcae0bb4f06",
			flags:    tapFlagDefaults("detect-tunneling", "true", "dns-port", "53", "domain", "", "domains-file", "", "tunneling-command", "", "tunneling-debounce", "5m", "tunneling-threshold", "0.7", "udp-only", "false"),
			bindings: tapBindings("detect-tunneling", "dns.detect_tunneling", "dns-port", "tap.dns.ports", "domain", "tap.dns.domain_pattern", "domains-file", "tap.dns.domains_file", "tunneling-command", "processor.tunneling_command", "tunneling-debounce", "processor.tunneling_debounce", "tunneling-threshold", "processor.tunneling_threshold", "udp-only", "tap.dns.udp_only"),
		},
		"http": {
			cmd: httpTapCmd, short: "Standalone HTTP capture with full processor capabilities",
			helpHash: "1b2fcd07cf540b62875beaf435e99a34bdb11024d8afec1522f898520c93523a",
			flags:    tapFlagDefaults("capture-body", "false", "content-type", "", "content-types-file", "", "host", "", "hosts-file", "", "http-port", "80,8080,8000,3000,8888", "keywords-file", "", "max-body-size", "65536", "method", "", "path", "", "paths-file", "", "status", "", "tls-keylog", "", "tls-keylog-pipe", "", "user-agent", "", "user-agents-file", ""),
			bindings: tapBindings("capture-body", "tap.http.capture_body", "content-type", "tap.http.content_type_pattern", "content-types-file", "tap.http.content_types_file", "host", "tap.http.host_pattern", "hosts-file", "tap.http.hosts_file", "http-port", "tap.http.ports", "keywords-file", "tap.http.keywords_file", "max-body-size", "tap.http.max_body_size", "method", "tap.http.methods", "path", "tap.http.path_pattern", "paths-file", "tap.http.paths_file", "status", "tap.http.status_codes", "tls-keylog", "tap.http.tls_keylog", "tls-keylog-pipe", "tap.http.tls_keylog_pipe", "user-agent", "tap.http.user_agent_pattern", "user-agents-file", "tap.http.user_agents_file"),
		},
		"tls": {
			cmd: tlsTapCmd, short: "Standalone TLS capture with full processor capabilities",
			helpHash: "ff1df628bf10e450868902b9d1a9a9d315292f683333b65d01ded15f324721e4",
			flags:    tapFlagDefaults("sni", "", "sni-file", "", "tls-port", "443"),
			bindings: tapBindings("sni", "tap.tls.sni_pattern", "sni-file", "tap.tls.sni_file", "tls-port", "tap.tls.ports"),
		},
		"email": {
			cmd: emailTapCmd, short: "Standalone email capture with full processor capabilities",
			helpHash: "44a9ce52c7fd191e0da6c90f92f3abefb42109c8e157bbeea68d47576ed98af2",
			flags:    tapFlagDefaults("address", "", "addresses-file", "", "capture-body", "false", "command", "", "imap-port", "143,993", "keywords-file", "", "mailbox", "", "max-body-size", "65536", "pop3-port", "110,995", "protocol", "all", "recipient", "", "recipients-file", "", "sender", "", "senders-file", "", "smtp-port", "25,587,465", "subject", "", "subjects-file", ""),
			bindings: tapBindings("address", "tap.email.address_pattern", "addresses-file", "tap.email.addresses_file", "capture-body", "tap.email.capture_body", "command", "tap.email.command_pattern", "imap-port", "tap.email.imap_ports", "keywords-file", "tap.email.keywords_file", "mailbox", "tap.email.mailbox_pattern", "max-body-size", "tap.email.max_body_size", "pop3-port", "tap.email.pop3_ports", "protocol", "tap.email.protocol", "recipient", "tap.email.recipient_pattern", "recipients-file", "tap.email.recipients_file", "sender", "tap.email.sender_pattern", "senders-file", "tap.email.senders_file", "smtp-port", "tap.email.smtp_ports", "subject", "tap.email.subject_pattern", "subjects-file", "tap.email.subjects_file"),
		},
		"voip": {
			cmd: voipTapCmd, short: "Standalone VoIP capture with full processor capabilities",
			helpHash: "68176cb3d362ae80a48c8339041aa7ab9508c245a99368ffeb5f10b33ac91a35",
			flags:    tapFlagDefaults("pattern-algorithm", "auto", "pattern-buffer-mb", "64", "pcap-closed-call-ttl", "1h0m0s", "pcap-grace-period", "5s", "per-call-pcap", "false", "per-call-pcap-dir", "./pcaps", "per-call-pcap-max-idle", "10m0s", "per-call-pcap-max-writers", "0", "per-call-pcap-pattern", "{timestamp}_{callid}.pcap", "rtp-port-range", "", "sip-port", "", "sip-user", "", "sipuser", "", "tcp-performance-mode", "balanced", "tcp-sip-idle-timeout", "0s", "udp-only", "false"),
			bindings: tapBindings("pattern-algorithm", "tap.voip.pattern_algorithm", "pattern-buffer-mb", "tap.voip.pattern_buffer_mb", "pcap-closed-call-ttl", "tap.per_call_pcap.closed_call_ttl", "pcap-grace-period", "tap.per_call_pcap.grace_period", "per-call-pcap", "tap.per_call_pcap.enabled", "per-call-pcap-dir", "tap.per_call_pcap.output_dir", "per-call-pcap-max-idle", "tap.per_call_pcap.max_idle", "per-call-pcap-max-writers", "tap.per_call_pcap.max_writers", "per-call-pcap-pattern", "tap.per_call_pcap.file_pattern", "rtp-port-range", "tap.voip.rtp_port_ranges", "sip-port", "tap.voip.sip_ports", "sip-user", "tap.voip.sip_user", "tcp-performance-mode", "tap.voip.tcp_performance_mode", "tcp-sip-idle-timeout", "voip.tcp_sip_idle_timeout", "udp-only", "tap.voip.udp_only"),
		},
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
