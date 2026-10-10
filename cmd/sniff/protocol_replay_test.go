//go:build cli || all

package sniff

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/endorses/lippycat/internal/pkg/email"
	httpprotocol "github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	tlsprotocol "github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func preserveReplayConfig(t *testing.T, values map[string]any) {
	t.Helper()
	for key, value := range values {
		old := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, old) })
	}
}

func TestProtocolReplayRetainsPCAPAndRebuildsTCPState(t *testing.T) {
	tests := []struct {
		name, protocol string
		packet         []byte
		run            func(context.Context, []string, string, capture.OfflineReplayOptions) error
	}{
		{"dns", "DNS", dnsPacket(t), dns.StartOfflineDNSSnifferWithReplay},
		{"http", "HTTP", tcpPacket(t, 49153, 80, []byte("GET /replay HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n")), httpprotocol.StartOfflineHTTPSnifferWithReplay},
		{"tls", "TLS", tcpPacket(t, 49154, 443, tlsClientHello()), tlsprotocol.StartOfflineTLSSnifferWithReplay},
		{"email-smtp", "SMTP", tcpPacket(t, 49155, 25, []byte("MAIL FROM:<alice@example.test>\r\n")), email.StartOfflineEmailSnifferWithReplay},
		{"email-imap", "IMAP", tcpPacket(t, 49156, 143, []byte("A1 LOGIN alice demo\r\n")), email.StartOfflineEmailSnifferWithReplay},
		{"email-pop3", "POP3", tcpPacket(t, 49157, 110, []byte("USER alice\r\n")), email.StartOfflineEmailSnifferWithReplay},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.pcap")
			output := filepath.Join(dir, "output.pcap")
			writeTestPCAP(t, input, tt.packet)
			scope, emailMode := tt.name, "all"
			if strings.HasPrefix(scope, "email-") {
				emailMode = strings.TrimPrefix(scope, "email-")
				scope = "email"
			}
			preserveReplayConfig(t, map[string]any{
				"sniff.format": "json", "sniff.quiet": false, scope + ".write_file": output,
				"dns.track_queries": true, "dns.detect_tunneling": false, "http.track_requests": true,
				"tls.track_connections": true, "email.track_sessions": true, "email.protocol": emailMode,
			})
			stdout, err := os.Create(filepath.Join(dir, "stdout.jsonl"))
			require.NoError(t, err)
			previous := os.Stdout
			os.Stdout = stdout
			t.Cleanup(func() { os.Stdout = previous })
			var passes []uint64
			err = tt.run(context.Background(), []string{input}, "", capture.OfflineReplayOptions{Count: 2, AfterPass: func(pass uint64) error { passes = append(passes, pass); return nil }})
			os.Stdout = previous
			require.NoError(t, err)
			require.NoError(t, stdout.Close())
			require.Equal(t, []uint64{1, 2}, passes)
			content, err := os.ReadFile(stdout.Name())
			require.NoError(t, err)
			// The same TCP tuple and sequence numbers must produce a full message again,
			// rather than becoming retransmissions in a previous pass's assembler.
			scanner := bufio.NewScanner(strings.NewReader(string(content)))
			var displays []types.PacketDisplay
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "{") {
					var display types.PacketDisplay
					require.NoError(t, json.Unmarshal(scanner.Bytes(), &display))
					displays = append(displays, display)
				}
			}
			require.NoError(t, scanner.Err())
			require.Len(t, displays, 2)
			require.Equal(t, tt.protocol, displays[0].Protocol)
			require.Equal(t, displays[0].Info, displays[1].Info)
			readBack, err := os.Open(output)
			require.NoError(t, err)
			defer func() { require.NoError(t, readBack.Close()) }()
			reader, err := pcapgo.NewReader(readBack)
			require.NoError(t, err)
			for range 2 {
				packet, info, err := reader.ReadPacketData()
				require.NoError(t, err)
				require.Equal(t, tt.packet, packet)
				require.True(t, time.Unix(10, 0).Equal(info.Timestamp))
			}
			_, _, err = reader.ReadPacketData()
			require.ErrorIs(t, err, io.EOF)

			// Cancellation during the gap must close the retained sink and return promptly.
			viper.Set("sniff.quiet", true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err = tt.run(ctx, []string{input}, "", capture.OfflineReplayOptions{Count: 0, Delay: time.Hour, AfterPass: func(uint64) error { cancel(); return nil }})
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}

func TestRunProtocolPassesReplayOptionsAndReturnsErrors(t *testing.T) {
	preserveReplayConfig(t, map[string]any{"sniff.replay_loop": 3, "sniff.replay_loop_delay": time.Millisecond, "logs.dir": "", "files.extract": false})
	oldRead, oldFilter := readFile, filter
	t.Cleanup(func() { readFile, filter = oldRead, oldFilter })
	readFile = "fixture.pcap"
	filter = ""
	failure := errors.New("replay fixture failure")
	var called bool
	hooks := sniffRuntimeHooks{BuildBPF: func(string) (string, error) { return "udp", nil }, StartLive: func(string, string) { t.Fatal("unexpected live ingress") }, StartReplay: func(ctx context.Context, files []string, bpf string, opts capture.OfflineReplayOptions) error {
		called = true
		require.Equal(t, []string{"fixture.pcap"}, files)
		require.Equal(t, "udp", bpf)
		require.Equal(t, 3, opts.Count)
		require.Equal(t, time.Millisecond, opts.Delay)
		return failure
	}}
	command := &cobra.Command{}
	command.SetContext(context.Background())
	require.ErrorIs(t, runProtocol(command, nil, protocolcatalog.Spec{Name: "test", Analyzer: "test"}, hooks), failure)
	require.True(t, called)
}
