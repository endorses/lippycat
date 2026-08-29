//go:build tap || all

package tap

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTapSourceConfigUsesProtocolSpec(t *testing.T) {
	oldInterfaces, oldBatchSize, oldBatchTimeout, oldBufferSize := interfaces, batchSize, batchTimeout, bufferSize
	t.Cleanup(func() {
		interfaces, batchSize, batchTimeout, bufferSize = oldInterfaces, oldBatchSize, oldBatchTimeout, oldBufferSize
	})
	interfaces = []string{"eth0", "eth1"}
	batchSize, batchTimeout, bufferSize = 42, 250, 2048

	got := tapSourceConfig(processor.Config{ProcessorID: "tap-test"}, "tcp port 443", ProtocolSpec{Name: "tls"})
	require.Equal(t, []string{"eth0", "eth1"}, got.Interfaces)
	require.Equal(t, "tcp port 443", got.BPFFilter)
	require.Equal(t, 42, got.BatchSize)
	require.Equal(t, 250*time.Millisecond, got.BatchTimeout)
	require.Equal(t, 2048, got.BufferSize)
	require.Equal(t, 1000, got.BatchBuffer)
	require.Equal(t, "tap-test", got.ProcessorID)
	require.Equal(t, "tls", got.ProtocolMode)
}

type tapProtocolContract struct {
	cmd      *cobra.Command
	short    string
	flags    map[string]string
	bindings map[string]string
}

func TestTapProtocolCLIContracts(t *testing.T) {
	contracts := map[string]tapProtocolContract{
		"dns": {
			cmd: dnsTapCmd, short: "Standalone DNS capture with full processor capabilities",
			flags:    tapFlagDefaults("detect-tunneling", "true", "dns-port", "53", "domain", "", "domains-file", "", "tunneling-command", "", "tunneling-debounce", "5m", "tunneling-threshold", "0.7", "udp-only", "false"),
			bindings: tapBindings("detect-tunneling", "dns.detect_tunneling", "dns-port", "tap.dns.ports", "domain", "tap.dns.domain_pattern", "domains-file", "tap.dns.domains_file", "tunneling-command", "processor.tunneling_command", "tunneling-debounce", "processor.tunneling_debounce", "tunneling-threshold", "processor.tunneling_threshold", "udp-only", "tap.dns.udp_only"),
		},
		"http": {
			cmd: httpTapCmd, short: "Standalone HTTP capture with full processor capabilities",
			flags:    tapFlagDefaults("capture-body", "false", "content-type", "", "content-types-file", "", "host", "", "hosts-file", "", "http-port", "80,8080,8000,3000,8888", "keywords-file", "", "max-body-size", "65536", "method", "", "path", "", "paths-file", "", "status", "", "tls-keylog", "", "tls-keylog-pipe", "", "user-agent", "", "user-agents-file", ""),
			bindings: tapBindings("capture-body", "tap.http.capture_body", "content-type", "tap.http.content_type_pattern", "content-types-file", "tap.http.content_types_file", "host", "tap.http.host_pattern", "hosts-file", "tap.http.hosts_file", "http-port", "tap.http.ports", "keywords-file", "tap.http.keywords_file", "max-body-size", "tap.http.max_body_size", "method", "tap.http.methods", "path", "tap.http.path_pattern", "paths-file", "tap.http.paths_file", "status", "tap.http.status_codes", "tls-keylog", "tap.http.tls_keylog", "tls-keylog-pipe", "tap.http.tls_keylog_pipe", "user-agent", "tap.http.user_agent_pattern", "user-agents-file", "tap.http.user_agents_file"),
		},
		"tls": {
			cmd: tlsTapCmd, short: "Standalone TLS capture with full processor capabilities",
			flags:    tapFlagDefaults("sni", "", "sni-file", "", "tls-port", "443"),
			bindings: tapBindings("sni", "tap.tls.sni_pattern", "sni-file", "tap.tls.sni_file", "tls-port", "tap.tls.ports"),
		},
		"email": {
			cmd: emailTapCmd, short: "Standalone email capture with full processor capabilities",
			flags:    tapFlagDefaults("address", "", "addresses-file", "", "capture-body", "false", "command", "", "imap-port", "143,993", "keywords-file", "", "mailbox", "", "max-body-size", "65536", "pop3-port", "110,995", "protocol", "all", "recipient", "", "recipients-file", "", "sender", "", "senders-file", "", "smtp-port", "25,587,465", "subject", "", "subjects-file", ""),
			bindings: tapBindings("address", "tap.email.address_pattern", "addresses-file", "tap.email.addresses_file", "capture-body", "tap.email.capture_body", "command", "tap.email.command_pattern", "imap-port", "tap.email.imap_ports", "keywords-file", "tap.email.keywords_file", "mailbox", "tap.email.mailbox_pattern", "max-body-size", "tap.email.max_body_size", "pop3-port", "tap.email.pop3_ports", "protocol", "tap.email.protocol", "recipient", "tap.email.recipient_pattern", "recipients-file", "tap.email.recipients_file", "sender", "tap.email.sender_pattern", "senders-file", "tap.email.senders_file", "smtp-port", "tap.email.smtp_ports", "subject", "tap.email.subject_pattern", "subjects-file", "tap.email.subjects_file"),
		},
		"voip": {
			cmd: voipTapCmd, short: "Standalone VoIP capture with full processor capabilities",
			flags:    tapFlagDefaults("pattern-algorithm", "auto", "pattern-buffer-mb", "64", "pcap-closed-call-ttl", "1h0m0s", "pcap-grace-period", "5s", "per-call-pcap", "false", "per-call-pcap-dir", "./pcaps", "per-call-pcap-max-idle", "10m0s", "per-call-pcap-max-writers", "0", "per-call-pcap-pattern", "{timestamp}_{callid}.pcap", "rtp-port-range", "", "sip-port", "", "sip-user", "", "sipuser", "", "tcp-performance-mode", "balanced", "tcp-sip-idle-timeout", "0s", "udp-only", "false"),
			bindings: tapBindings("pattern-algorithm", "tap.voip.pattern_algorithm", "pattern-buffer-mb", "tap.voip.pattern_buffer_mb", "pcap-closed-call-ttl", "tap.per_call_pcap.closed_call_ttl", "pcap-grace-period", "tap.per_call_pcap.grace_period", "per-call-pcap", "tap.per_call_pcap.enabled", "per-call-pcap-dir", "tap.per_call_pcap.output_dir", "per-call-pcap-max-idle", "tap.per_call_pcap.max_idle", "per-call-pcap-max-writers", "tap.per_call_pcap.max_writers", "per-call-pcap-pattern", "tap.per_call_pcap.file_pattern", "rtp-port-range", "tap.voip.rtp_port_ranges", "sip-port", "tap.voip.sip_ports", "sip-user", "tap.voip.sip_user", "tcp-performance-mode", "tap.voip.tcp_performance_mode", "tcp-sip-idle-timeout", "voip.tcp_sip_idle_timeout", "udp-only", "tap.voip.udp_only"),
		},
	}

	allKeys := make(map[string]struct{}, len(viper.AllKeys()))
	for _, key := range viper.AllKeys() {
		allKeys[strings.ToLower(key)] = struct{}{}
	}
	for name, contract := range contracts {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, name, contract.cmd.Use)
			require.Equal(t, contract.short, contract.cmd.Short)
			require.Contains(t, contract.cmd.Long, "Example:")
			require.Contains(t, contract.cmd.Long, "lc tap "+name)
			require.Equal(t, contract.flags, tapCommandFlagDefaults(contract.cmd))
			for flagName, key := range contract.bindings {
				require.NotNil(t, contract.cmd.Flags().Lookup(flagName), "binding references missing flag")
				require.Contains(t, allKeys, strings.ToLower(key), "missing Viper key for --%s", flagName)
			}
		})
	}
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
