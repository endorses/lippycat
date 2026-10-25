//go:build cli || all

package sniff

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestSniffTLSReportsCanonicalECHWithoutLogSink(t *testing.T) {
	preserveReplayConfig(t, map[string]any{
		"logs.dir": "", "logs.streams": []string{}, "files.extract": false,
		"sniff.replay_loop": 2, "sniff.replay_loop_delay": time.Duration(0),
		"sniff.quiet": true, "sniff.format": "text",
	})
	dir := t.TempDir()
	input := filepath.Join(dir, "segmented.pcap")
	file, err := os.Create(input)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	hello := tlsClientHello()
	// This fixture's ClientHello has one SNI extension; append opaque ECH.
	const extensionOffset = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 2
	extensions := binary.BigEndian.Uint16(hello[extensionOffset:])
	binary.BigEndian.PutUint16(hello[extensionOffset:], extensions+5)
	hello = append(hello, 0xfe, 0x0d, 0, 1, 0)
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(hello)-5))
	hello[8] = byte(len(hello) - 9)
	seq := uint32(1000)
	for i, payload := range [][]byte{nil, hello[:7], hello[:7], hello[7:]} {
		eth, ip := ethernetIPv4(layers.IPProtocolTCP)
		tcp := &layers.TCP{SrcPort: 49000, DstPort: 443, Seq: seq, SYN: i == 0, ACK: i != 0, Window: 65535}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		packet := serializePacket(t, eth, ip, tcp, gopacket.Payload(payload))
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(100+int64(i), 0), CaptureLength: len(packet), Length: len(packet)}, packet))
		if i == 0 {
			seq++
		}
		if i == 2 {
			seq += 7
		}
	}
	require.NoError(t, file.Close())
	stdout, err := os.Create(filepath.Join(dir, "stdout"))
	require.NoError(t, err)
	previous := os.Stdout
	os.Stdout = stdout
	t.Cleanup(func() { os.Stdout = previous })
	oldRead, oldFilter := readFile, filter
	readFile, filter = input, ""
	t.Cleanup(func() { readFile, filter = oldRead, oldFilter })
	command := &cobra.Command{}
	command.SetContext(context.Background())
	err = runProtocol(command, nil, protocolcatalog.Spec{Name: "tls", Analyzer: protocolcatalog.AnalyzerTLS}, tlsRuntimeHooks)
	os.Stdout = previous
	require.NoError(t, stdout.Close())
	require.NoError(t, err)
	content, err := os.ReadFile(stdout.Name())
	require.NoError(t, err)
	require.Contains(t, string(content), "Completely framed ClientHello observations: 1")
	require.Equal(t, 2, strings.Count(string(content), "ECH offered / ClientHello: 1 / 1"), "each replay summary covers one pass")
	require.NotContains(t, string(content), "ECH offered / ClientHello: 2 / 2")
}
