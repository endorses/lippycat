//go:build cli || all

package sniff

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type sniffProtocolContract struct {
	cmd      *cobra.Command
	flags    map[string]string
	bindings map[string]string
}

func TestSniffProtocolCLIContracts(t *testing.T) {
	helpHashes := map[string]string{
		"dns":   "d3a2af6bbe6dac200da1cbe0b8d5b1db13433b793284147d2bd89fc83857de75",
		"email": "6a1ee5a633253c471a9c037992839574256761837c3f7699d4b0e1a24661cea4",
		"http":  "0a1672d2e751724ff51a106810160bf8af449e51be4e6e9ea20f2fd06014d07b",
		"tls":   "f36cec27a08e52741ca5758d8acb7b706bb4fb8553bcd0ba68ce5b8daeae387b",
		"voip":  "685967ddfc2bffe7bd3e8ea96cecac950f4aee5003a5c43d128c623f079dfc2e",
	}
	contracts := map[string]sniffProtocolContract{
		"dns": {
			cmd:      dnsCmd,
			flags:    flagDefaults("domain", "", "domains-file", "", "udp-only", "false", "dns-port", "53", "track-queries", "true", "detect-tunneling", "true", "write-file", ""),
			bindings: bindings("domain", "dns.domain_pattern", "domains-file", "dns.domains_file", "udp-only", "dns.udp_only", "dns-port", "dns.ports", "track-queries", "dns.track_queries", "detect-tunneling", "dns.detect_tunneling"),
		},
		"tls": {
			cmd:      tlsCmd,
			flags:    flagDefaults("sni", "", "sni-file", "", "ja3", "", "ja3-file", "", "ja3s", "", "ja3s-file", "", "ja4", "", "ja4-file", "", "tls-port", "443", "track-connections", "true", "write-file", ""),
			bindings: bindings("sni", "tls.sni_pattern", "sni-file", "tls.sni_file", "ja3", "tls.ja3", "ja3-file", "tls.ja3_file", "ja3s", "tls.ja3s", "ja3s-file", "tls.ja3s_file", "ja4", "tls.ja4", "ja4-file", "tls.ja4_file", "tls-port", "tls.ports", "track-connections", "tls.track_connections"),
		},
		"http": {
			cmd:      httpCmd,
			flags:    flagDefaults("host", "", "path", "", "method", "", "status", "", "user-agent", "", "content-type", "", "hosts-file", "", "paths-file", "", "user-agents-file", "", "content-types-file", "", "keywords-file", "", "http-port", "80,8080,8000,3000,8888", "track-requests", "true", "write-file", "", "capture-body", "false", "max-body-size", "65536", "tls-keylog", "", "tls-keylog-pipe", ""),
			bindings: bindings("host", "http.host_pattern", "path", "http.path_pattern", "method", "http.methods", "status", "http.status_codes", "user-agent", "http.user_agent_pattern", "content-type", "http.content_type_pattern", "hosts-file", "http.hosts_file", "paths-file", "http.paths_file", "user-agents-file", "http.user_agents_file", "content-types-file", "http.content_types_file", "keywords-file", "http.keywords_file", "http-port", "http.ports", "track-requests", "http.track_requests", "capture-body", "http.capture_body", "max-body-size", "http.max_body_size", "tls-keylog", "http.tls_keylog", "tls-keylog-pipe", "http.tls_keylog_pipe"),
		},
		"email": {
			cmd:      emailCmd,
			flags:    flagDefaults("address", "", "sender", "", "recipient", "", "subject", "", "mailbox", "", "command", "", "addresses-file", "", "senders-file", "", "recipients-file", "", "subjects-file", "", "keywords-file", "", "protocol", "all", "smtp-port", "25,587,465", "imap-port", "143,993", "pop3-port", "110,995", "track-sessions", "true", "write-file", "", "capture-body", "false", "max-body-size", "65536"),
			bindings: bindings("address", "email.address_pattern", "sender", "email.sender_pattern", "recipient", "email.recipient_pattern", "subject", "email.subject_pattern", "mailbox", "email.mailbox_pattern", "command", "email.command_pattern", "addresses-file", "email.addresses_file", "senders-file", "email.senders_file", "recipients-file", "email.recipients_file", "subjects-file", "email.subjects_file", "keywords-file", "email.keywords_file", "protocol", "email.protocol", "smtp-port", "email.smtp_ports", "imap-port", "email.imap_ports", "pop3-port", "email.pop3_ports", "track-sessions", "email.track_sessions", "capture-body", "email.capture_body", "max-body-size", "email.max_body_size"),
		},
		"voip": {
			cmd:      voipCmd,
			flags:    flagDefaults("sip-user", "", "sipuser", "", "write-file", "", "udp-only", "false", "sip-port", "", "rtp-port-range", "", "pattern-algorithm", "auto", "pattern-buffer-mb", "64", "tcp-max-goroutines", "0", "tcp-cleanup-interval", "0s", "tcp-buffer-max-age", "0s", "tcp-stream-max-queue-time", "0s", "max-tcp-buffers", "0", "tcp-stream-timeout", "0s", "tcp-assembler-max-pages", "0", "tcp-performance-mode", "", "tcp-buffer-strategy", "", "enable-backpressure", "false", "memory-optimization", "false", "tcp-sip-idle-timeout", "0s", "pcap-grace-period", "5s"),
			bindings: bindings("udp-only", "voip.udp_only", "sip-port", "voip.sip_ports", "rtp-port-range", "voip.rtp_port_ranges", "pattern-algorithm", "voip.pattern_algorithm", "pattern-buffer-mb", "voip.pattern_buffer_mb", "tcp-max-goroutines", "voip.max_goroutines", "tcp-cleanup-interval", "voip.tcp_cleanup_interval", "tcp-buffer-max-age", "voip.tcp_buffer_max_age", "tcp-stream-max-queue-time", "voip.tcp_stream_max_queue_time", "max-tcp-buffers", "voip.max_tcp_buffers", "tcp-stream-timeout", "voip.tcp_stream_timeout", "tcp-assembler-max-pages", "voip.tcp_assembler_max_pages", "tcp-performance-mode", "voip.tcp_performance_mode", "tcp-buffer-strategy", "voip.tcp_buffer_strategy", "enable-backpressure", "voip.enable_backpressure", "memory-optimization", "voip.memory_optimization", "tcp-sip-idle-timeout", "voip.tcp_sip_idle_timeout", "pcap-grace-period", "voip.pcap_grace_period"),
		},
	}

	for name, contract := range contracts {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, name, contract.cmd.Use)
			require.Equal(t, contract.flags, commandFlagDefaults(contract.cmd))
			require.Equal(t, helpHashes[name], renderedHelpHash(t, contract.cmd), "full rendered help changed")

			for flagName, key := range contract.bindings {
				assertExactViperBinding(t, contract.cmd, flagName, key)
			}
		})
	}
}

func renderedHelpHash(t *testing.T, cmd *cobra.Command) string {
	t.Helper()
	var output bytes.Buffer
	oldOut := cmd.OutOrStdout()
	cmd.SetOut(&output)
	t.Cleanup(func() { cmd.SetOut(oldOut) })
	require.NoError(t, cmd.Help())
	return fmt.Sprintf("%x", sha256.Sum256(output.Bytes()))
}

func assertExactViperBinding(t *testing.T, cmd *cobra.Command, flagName, key string) {
	t.Helper()
	flag := cmd.Flags().Lookup(flagName)
	require.NotNil(t, flag, "binding references missing flag")

	oldValue, oldChanged := flag.Value.String(), flag.Changed
	defer func() {
		require.NoError(t, flag.Value.Set(oldValue))
		flag.Changed = oldChanged
	}()
	require.Equal(t, flag.DefValue, viper.GetString(key), "unexpected baseline for Viper key %q", key)
	require.NoError(t, flag.Value.Set(distinctFlagValue(flag)))
	flag.Changed = true
	require.Equal(t, flag.Value.String(), viper.GetString(key), "Viper key %q is not bound to --%s", key, flagName)
}

func distinctFlagValue(flag *pflag.Flag) string {
	switch flag.Value.Type() {
	case "bool":
		if flag.DefValue == "true" {
			return "false"
		}
		return "true"
	case "duration":
		return "37s"
	case "int":
		return "37123"
	default:
		return "binding-" + flag.Name
	}
}

func commandFlagDefaults(cmd *cobra.Command) map[string]string {
	result := make(map[string]string)
	cmd.Flags().VisitAll(func(flag *pflag.Flag) { result[flag.Name] = flag.DefValue })
	return result
}

func flagDefaults(values ...string) map[string]string { return pairs(values...) }
func bindings(values ...string) map[string]string     { return pairs(values...) }

func pairs(values ...string) map[string]string {
	if len(values)%2 != 0 {
		panic(fmt.Sprintf("odd contract pair count: %d", len(values)))
	}
	result := make(map[string]string, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		result[values[i]] = values[i+1]
	}
	return result
}

func TestSniffProtocolContractNamesAreStable(t *testing.T) {
	names := []string{
		protocolcatalog.MustLookup("dns").Name,
		protocolcatalog.MustLookup("email").Name,
		protocolcatalog.MustLookup("http").Name,
		protocolcatalog.MustLookup("tls").Name,
		protocolcatalog.MustLookup("voip").Name,
	}
	sort.Strings(names)
	require.Equal(t, []string{"dns", "email", "http", "tls", "voip"}, names)
}
