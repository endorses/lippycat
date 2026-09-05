//go:build tui || all

package tui

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tls/decrypt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineIndexerTLSPlaintextLimit(t *testing.T) {
	dir := t.TempDir()
	path, keysPath := filepath.Join(dir, "tls.pcap"), filepath.Join(dir, "keys.log")
	random, secret := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	require.NoError(t, os.WriteFile(keysPath, []byte(fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, secret, random, secret)), 0600))
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeRaw))
	var packetIndex int
	seqs := [2]uint32{100, 100}
	writeRecord := func(server bool, kind byte, payload []byte) {
		header := []byte{kind, 3, 3, 0, 0}
		binary.BigEndian.PutUint16(header[3:], uint16(len(payload)))
		record := append(header, payload...)
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
		tcp := &layers.TCP{SrcPort: 12345, DstPort: 443, ACK: true, PSH: true, Window: 65535}
		i := 0
		if server {
			i = 1
			ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
			tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
		}
		tcp.Seq = seqs[i]
		seqs[i] += uint32(len(record))
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(record)))
		raw := buf.Bytes()
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(100, int64(packetIndex)*int64(time.Millisecond)), CaptureLength: len(raw), Length: len(raw)}, raw))
		packetIndex++
	}
	handshake := func(kind byte, body []byte) []byte {
		header := []byte{kind, 0, 0, 0}
		header[2], header[3] = byte(len(body)>>8), byte(len(body))
		return append(header, body...)
	}
	client := append([]byte{3, 3}, random...)
	client = append(client, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	writeRecord(false, 22, handshake(1, client))
	server := append([]byte{3, 3}, bytes.Repeat([]byte{3}, 32)...)
	server = append(server, 0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	writeRecord(true, 22, handshake(2, server))
	suite := decrypt.GetCipherSuiteInfo(0x1301)
	keys := decrypt.DeriveTrafficKeys(suite.HashAlgorithm, secret, suite)
	block, err := aes.NewCipher(keys.Key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	inner := append(bytes.Repeat([]byte("a"), 16384), byte(decrypt.ContentTypeApplicationData))
	for seq := uint64(0); seq < 1025; seq++ {
		fragment := aead.Seal(nil, decrypt.ConstructTLS13Nonce(keys.IV, seq), inner, decrypt.ComputeTLS13AdditionalData(len(inner)+aead.Overhead()))
		writeRecord(false, 23, fragment)
	}
	require.NoError(t, f.Close())
	storage := testOfflineStorage(t)
	session, err := indexOfflineDataset(context.Background(), storage, 1, OfflineAnalysisConfig{Inputs: []string{path}, TLSKeylog: keysPath, EventCapacity: 8}, nil)
	if session != nil {
		t.Cleanup(func() { require.NoError(t, session.Close()) })
	}
	require.ErrorIs(t, err, decrypt.ErrPlaintextLimit)
	require.Nil(t, session)
	require.Zero(t, storage.Resources().DiskBytes)
}
