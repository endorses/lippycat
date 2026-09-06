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

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tls/decrypt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineCompactTLSResultsSurviveKeyRemoval(t *testing.T) {
	dir := t.TempDir()
	path, keyPath := filepath.Join(dir, "tls.pcap"), filepath.Join(dir, "keys.log")
	random, secret := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	require.NoError(t, os.WriteFile(keyPath, []byte(fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, secret, random, secret)), 0600))
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriterNanos(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeRaw))
	seqs, index := [2]uint32{100, 100}, 0
	write := func(server bool, kind byte, payload []byte) {
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
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(index), 0), CaptureLength: len(raw), Length: len(raw)}, raw))
		index++
	}
	handshake := func(kind byte, body []byte) []byte {
		return append([]byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	}
	client := append([]byte{3, 3}, random...)
	client = append(client, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	write(false, 22, handshake(1, client))
	server := append([]byte{3, 3}, bytes.Repeat([]byte{3}, 32)...)
	server = append(server, 0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	write(true, 22, handshake(2, server))
	suite := decrypt.GetCipherSuiteInfo(0x1301)
	keys := decrypt.DeriveTrafficKeys(suite.HashAlgorithm, secret, suite)
	block, err := aes.NewCipher(keys.Key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	plaintext := []byte("GET /frozen HTTP/1.1\r\nHost: offline.example\r\n\r\n")
	inner := append(bytes.Clone(plaintext), byte(decrypt.ContentTypeApplicationData))
	write(false, 23, aead.Seal(nil, decrypt.ConstructTLS13Nonce(keys.IV, 0), inner, decrypt.ComputeTLS13AdditionalData(len(inner)+aead.Overhead())))
	require.NoError(t, f.Close())
	cfg := OfflineAnalysisConfig{Inputs: []string{path}, TLSKeylog: keyPath, EventCapacity: 32}
	runOfflineCompactOracle(t, cfg, indexOfflineCompactDataset)
	session, err := indexOfflineCompactDataset(context.Background(), testOfflineStorage(t), 92, cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })
	require.NoError(t, os.Remove(keyPath))
	for _, id := range []offline.PacketID{2, 0, 1, 2} {
		_, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 92}, id)
		require.NoError(t, err)
		clientData, serverData := session.TLSDecryptor.GetDecryptedData("192.0.2.1", "192.0.2.2", "12345", "443")
		require.Equal(t, plaintext, clientData)
		require.Empty(t, serverData)
	}
}
