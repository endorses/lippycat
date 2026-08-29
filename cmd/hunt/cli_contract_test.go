//go:build hunter || all

package hunt

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHuntPersistentFlagContract(t *testing.T) {
	assert.Equal(t, "hunt", HuntCmd.Use)
	assert.Equal(t, "Run as hunter node (edge packet capture)", HuntCmd.Short)
	assert.Contains(t, HuntCmd.Long, "Example:")
	assert.Contains(t, HuntCmd.Long, "lc hunt --processor processor.example.com:55555")

	want := map[string]string{
		"batch-queue-size": "0", "batch-size": "64", "batch-timeout": "100",
		"buffer-size": "10000", "debug-allow-non-loopback": "false", "debug-listen": "",
		"disk-buffer": "false", "disk-buffer-dir": "/var/tmp/lippycat-buffer", "disk-buffer-max-mb": "1024",
		"esp-heuristic": "false", "esp-icv-size": "-1", "esp-null": "false", "filter": "",
		"hunter-id": "", "id": "", "insecure": "false", "interface": "[any]",
		"no-filter-policy": "deny", "pcap-buffer-size": "16777216", "processor": "", "promisc": "false",
		"tls-ca": "", "tls-cert": "", "tls-key": "", "tls-skip-verify": "false",
	}
	assert.Equal(t, want, flagDefaults(HuntCmd.PersistentFlags()))
}

func TestHuntProtocolCLIContract(t *testing.T) {
	tests := []struct {
		name, short, example string
		cmd                  *cobra.Command
		flags                map[string]string
	}{
		{"dns", "Run as DNS hunter with query filtering", "lc hunt dns --processor processor:55555", dnsHuntCmd, map[string]string{"detect-tunneling": "true", "dns-port": "53", "udp-only": "false"}},
		{"http", "Run as HTTP hunter with content filtering", "lc hunt http --processor processor:55555", httpHuntCmd, map[string]string{"capture-body": "false", "host": "", "http-port": "80,8080,8000,3000,8888", "keywords": "", "max-body-size": "65536", "method": "", "path": "", "status": "", "tls-keylog": "", "tls-keylog-pipe": ""}},
		{"tls", "Run as TLS hunter with fingerprint filtering", "lc hunt tls --processor processor:55555", tlsHuntCmd, map[string]string{"tls-port": "443"}},
		{"email", "Run as Email hunter with SMTP/IMAP/POP3 filtering", "lc hunt email --processor processor:55555", emailHuntCmd, map[string]string{"capture-body": "false", "command": "", "imap-port": "143,993", "keywords": "", "mailbox": "", "max-body-size": "65536", "pop3-port": "110,995", "protocol": "all", "recipient": "", "sender": "", "smtp-port": "25,587,465", "subject": ""}},
		{"voip", "Run as VoIP hunter with call buffering", "lc hunt voip --processor processor:55555", voipHuntCmd, map[string]string{"pattern-algorithm": "auto", "pattern-buffer-mb": "64", "rtp-port-range": "", "sip-port": "", "tcp-sip-idle-timeout": "0s", "udp-only": "false"}},
	}

	rootFlags := flagDefaults(HuntCmd.PersistentFlags())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.name, tt.cmd.Use)
			assert.Equal(t, tt.short, tt.cmd.Short)
			assert.Contains(t, tt.cmd.Long, "Example:")
			assert.Contains(t, tt.cmd.Long, tt.example)
			assert.Equal(t, tt.flags, flagDefaults(tt.cmd.LocalNonPersistentFlags()))

			for name, defaultValue := range rootFlags {
				flag := tt.cmd.InheritedFlags().Lookup(name)
				require.NotNilf(t, flag, "missing inherited flag %q", name)
				assert.Equal(t, defaultValue, flag.DefValue, name)
			}
		})
	}
}

func TestHuntViperBindingContract(t *testing.T) {
	wantKeys := []string{
		"dns.detect_tunneling", "esp_heuristic", "esp_icv_size", "esp_null",
		"hunter.batch_queue_size", "hunter.batch_size", "hunter.batch_timeout_ms", "hunter.bpf_filter", "hunter.buffer_size",
		"hunter.debug_allow_non_loopback", "hunter.debug_listen",
		"hunter.disk_buffer.dir", "hunter.disk_buffer.enabled", "hunter.disk_buffer.max_mb",
		"hunter.dns.ports", "hunter.dns.udp_only",
		"hunter.email.capture_body", "hunter.email.command", "hunter.email.imap_ports", "hunter.email.keywords", "hunter.email.mailbox", "hunter.email.max_body_size", "hunter.email.pop3_ports", "hunter.email.protocol", "hunter.email.recipient", "hunter.email.sender", "hunter.email.smtp_ports", "hunter.email.subject",
		"hunter.http.capture_body", "hunter.http.host", "hunter.http.keywords", "hunter.http.max_body_size", "hunter.http.method", "hunter.http.path", "hunter.http.ports", "hunter.http.status", "hunter.http.tls_keylog", "hunter.http.tls_keylog_pipe",
		"hunter.hunter_id", "hunter.id", "hunter.insecure", "hunter.interfaces", "hunter.no_filter_policy", "hunter.processor_addr",
		"hunter.tls.ca_file", "hunter.tls.cert_file", "hunter.tls.key_file", "hunter.tls.ports", "hunter.tls.skip_verify",
		"hunter.voip.rtp_port_ranges", "hunter.voip.sip_ports", "hunter.voip.udp_only",
		"pcap_buffer_size", "promiscuous", "voip.pattern_algorithm", "voip.pattern_buffer_mb", "voip.tcp_sip_idle_timeout",
	}

	allKeys := make(map[string]struct{}, len(viper.AllKeys()))
	for _, key := range viper.AllKeys() {
		allKeys[strings.ToLower(key)] = struct{}{}
	}
	for _, key := range wantKeys {
		_, ok := allKeys[key]
		assert.Truef(t, ok, "Viper key %q is not bound", key)
	}
}

func flagDefaults(flags *pflag.FlagSet) map[string]string {
	defaults := make(map[string]string)
	flags.VisitAll(func(flag *pflag.Flag) {
		defaults[flag.Name] = flag.DefValue
	})
	return defaults
}
