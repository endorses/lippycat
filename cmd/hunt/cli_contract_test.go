//go:build hunter || all

package hunt

import (
	"bytes"
	"crypto/sha256"
	"fmt"
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
		"event-delivery-profile": "reliable", "event-fallback-to-packets": "false",
		"event-spool-dir": "/var/tmp/lippycat-event-spool", "event-spool-exhaustion-policy": "drop_oldest",
		"event-spool-max-age": "24h0m0s", "event-spool-max-bytes": "1073741824", "forward-mode": "packets",
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
	bindings := map[string]*pflag.Flag{
		"hunter.processor_addr": HuntCmd.PersistentFlags().Lookup("processor"), "hunter.id": HuntCmd.PersistentFlags().Lookup("id"), "hunter.hunter_id": HuntCmd.PersistentFlags().Lookup("id"),
		"hunter.interfaces": HuntCmd.PersistentFlags().Lookup("interface"), "hunter.bpf_filter": HuntCmd.PersistentFlags().Lookup("filter"), "hunter.buffer_size": HuntCmd.PersistentFlags().Lookup("buffer-size"),
		"hunter.batch_size": HuntCmd.PersistentFlags().Lookup("batch-size"), "hunter.batch_timeout_ms": HuntCmd.PersistentFlags().Lookup("batch-timeout"), "hunter.batch_queue_size": HuntCmd.PersistentFlags().Lookup("batch-queue-size"),
		"promiscuous": HuntCmd.PersistentFlags().Lookup("promisc"), "pcap_buffer_size": HuntCmd.PersistentFlags().Lookup("pcap-buffer-size"),
		"hunter.disk_buffer.enabled": HuntCmd.PersistentFlags().Lookup("disk-buffer"), "hunter.disk_buffer.dir": HuntCmd.PersistentFlags().Lookup("disk-buffer-dir"), "hunter.disk_buffer.max_mb": HuntCmd.PersistentFlags().Lookup("disk-buffer-max-mb"),
		"hunter.tls.cert_file": HuntCmd.PersistentFlags().Lookup("tls-cert"), "hunter.tls.key_file": HuntCmd.PersistentFlags().Lookup("tls-key"), "hunter.tls.ca_file": HuntCmd.PersistentFlags().Lookup("tls-ca"), "hunter.tls.skip_verify": HuntCmd.PersistentFlags().Lookup("tls-skip-verify"),
		"hunter.insecure": HuntCmd.PersistentFlags().Lookup("insecure"), "hunter.no_filter_policy": HuntCmd.PersistentFlags().Lookup("no-filter-policy"),
		"esp_null": HuntCmd.PersistentFlags().Lookup("esp-null"), "esp_heuristic": HuntCmd.PersistentFlags().Lookup("esp-heuristic"), "esp_icv_size": HuntCmd.PersistentFlags().Lookup("esp-icv-size"),
		"hunter.debug_listen": HuntCmd.PersistentFlags().Lookup("debug-listen"), "hunter.debug_allow_non_loopback": HuntCmd.PersistentFlags().Lookup("debug-allow-non-loopback"),
		"hunter.dns.ports": dnsHuntCmd.Flags().Lookup("dns-port"), "hunter.dns.udp_only": dnsHuntCmd.Flags().Lookup("udp-only"), "dns.detect_tunneling": dnsHuntCmd.Flags().Lookup("detect-tunneling"),
		"hunter.http.ports": httpHuntCmd.Flags().Lookup("http-port"), "hunter.http.host": httpHuntCmd.Flags().Lookup("host"), "hunter.http.path": httpHuntCmd.Flags().Lookup("path"), "hunter.http.method": httpHuntCmd.Flags().Lookup("method"), "hunter.http.status": httpHuntCmd.Flags().Lookup("status"), "hunter.http.keywords": httpHuntCmd.Flags().Lookup("keywords"), "hunter.http.capture_body": httpHuntCmd.Flags().Lookup("capture-body"), "hunter.http.max_body_size": httpHuntCmd.Flags().Lookup("max-body-size"), "hunter.http.tls_keylog": httpHuntCmd.Flags().Lookup("tls-keylog"), "hunter.http.tls_keylog_pipe": httpHuntCmd.Flags().Lookup("tls-keylog-pipe"),
		"hunter.tls.ports":      tlsHuntCmd.Flags().Lookup("tls-port"),
		"hunter.email.protocol": emailHuntCmd.Flags().Lookup("protocol"), "hunter.email.smtp_ports": emailHuntCmd.Flags().Lookup("smtp-port"), "hunter.email.imap_ports": emailHuntCmd.Flags().Lookup("imap-port"), "hunter.email.pop3_ports": emailHuntCmd.Flags().Lookup("pop3-port"), "hunter.email.sender": emailHuntCmd.Flags().Lookup("sender"), "hunter.email.recipient": emailHuntCmd.Flags().Lookup("recipient"), "hunter.email.subject": emailHuntCmd.Flags().Lookup("subject"), "hunter.email.keywords": emailHuntCmd.Flags().Lookup("keywords"), "hunter.email.mailbox": emailHuntCmd.Flags().Lookup("mailbox"), "hunter.email.command": emailHuntCmd.Flags().Lookup("command"), "hunter.email.capture_body": emailHuntCmd.Flags().Lookup("capture-body"), "hunter.email.max_body_size": emailHuntCmd.Flags().Lookup("max-body-size"),
		"hunter.voip.udp_only": voipHuntCmd.Flags().Lookup("udp-only"), "hunter.voip.sip_ports": voipHuntCmd.Flags().Lookup("sip-port"), "hunter.voip.rtp_port_ranges": voipHuntCmd.Flags().Lookup("rtp-port-range"), "voip.pattern_algorithm": voipHuntCmd.Flags().Lookup("pattern-algorithm"), "voip.pattern_buffer_mb": voipHuntCmd.Flags().Lookup("pattern-buffer-mb"), "voip.tcp_sip_idle_timeout": voipHuntCmd.Flags().Lookup("tcp-sip-idle-timeout"),
	}
	for key, flag := range bindings {
		t.Run(key, func(t *testing.T) {
			require.NotNil(t, flag)
			original, originalChanged := flag.Value.String(), flag.Changed
			fixture := bindingFixture(flag.Value.Type(), original)
			require.NoError(t, flag.Value.Set(fixture))
			flag.Changed = true
			t.Cleanup(func() {
				require.NoError(t, flag.Value.Set(original))
				flag.Changed = originalChanged
			})
			if flag.Value.Type() == "stringSlice" {
				assert.Equal(t, []string{"phase-seven-a", "phase-seven-b"}, viper.Get(key), "Viper key is not bound to --%s", flag.Name)
			} else {
				assert.Equal(t, flag.Value.String(), fmt.Sprint(viper.Get(key)), "Viper key is not bound to --%s", flag.Name)
			}
		})
	}
}

func bindingFixture(flagType, original string) string {
	switch flagType {
	case "bool":
		return fmt.Sprint(original != "true")
	case "int":
		return "314159"
	case "duration":
		return "37s"
	case "stringSlice":
		return "phase-seven-a,phase-seven-b"
	default:
		return "phase-seven-fixture"
	}
}

func TestHuntRenderedHelpSnapshots(t *testing.T) {
	want := map[string]string{
		"hunt":  "b794308e4c6ba11adc64188c6667f50b4da1a65306efcffa4c1a95565ea8ce60",
		"dns":   "176ac84328313d2191394248783ad43c9fc458a1171085ce907bc3f766b00df4",
		"http":  "0f80f83cbb19af341b108d20884c95fc4656c602b0d99b4f9d2dc8b9d5974ace",
		"tls":   "21b86049b07be0abad41385e3bd2b86bf4c476edcad941876238a015a3d1f961",
		"email": "4ac2249ed1b0fd02ddf7e226e979b5071c90fd3b590aa1107db42b4db047d9bf",
		"voip":  "bac4ac2b2727af11536689ba09af249d725cb1784632d7dfc8748f0ed7154b8b",
	}
	commands := map[string]*cobra.Command{"hunt": HuntCmd, "dns": dnsHuntCmd, "http": httpHuntCmd, "tls": tlsHuntCmd, "email": emailHuntCmd, "voip": voipHuntCmd}
	for name, cmd := range commands {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			originalOut := cmd.OutOrStdout()
			cmd.SetOut(&output)
			t.Cleanup(func() { cmd.SetOut(originalOut) })
			require.NoError(t, cmd.Help())
			digest := fmt.Sprintf("%x", sha256.Sum256(output.Bytes()))
			assert.Equal(t, want[name], digest, "rendered help changed; review it before updating this snapshot")
		})
	}
}

func flagDefaults(flags *pflag.FlagSet) map[string]string {
	defaults := make(map[string]string)
	flags.VisitAll(func(flag *pflag.Flag) {
		defaults[flag.Name] = flag.DefValue
	})
	return defaults
}
