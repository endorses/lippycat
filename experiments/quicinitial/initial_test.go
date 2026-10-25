//go:build cli || hunter || processor || tap || tui || all

package quicinitial

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func reference(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/rfc9001-" + name + ".hex")
	require.NoError(t, err)
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	require.NoError(t, err)
	return data
}
func session(t testing.TB) *Session {
	t.Helper()
	s, err := NewSession([]byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08})
	require.NoError(t, err)
	t.Cleanup(s.Close)
	return s
}

func TestRFC9001ClientAndServer(t *testing.T) {
	s := session(t)
	client := s.Feed(reference(t, "client"), Client)
	require.Len(t, client, 1)
	r := client[0]
	require.Equal(t, Complete, r.Reason)
	require.Equal(t, uint64(2), r.Header.PacketNumber)
	require.Equal(t, 4, r.Header.PacketNumberLength)
	require.Equal(t, 1200, r.Header.PacketBytes)
	require.Equal(t, "example.com", r.TLS.SNI)
	require.Equal(t, []string{"alpn"}, r.TLS.ALPNProtocols)
	require.True(t, r.TLS.ClientHelloObserved)
	require.False(t, r.TLS.ECHOffered)
	require.Empty(t, r.TLS.JA4Fingerprint)
	require.Zero(t, r.TLS.RecordVersion)
	require.Len(t, r.ClientHello, 241)
	require.True(t, r.TransportParametersObserved)
	require.Contains(t, r.Parameters, Parameter{15, "8394c8f03e515708"})
	server := s.Feed(reference(t, "server"), Server)
	require.Len(t, server, 1)
	require.Equal(t, ServerHandshake, server[0].Reason)
	require.Equal(t, uint64(1), server[0].Header.PacketNumber)
	require.Equal(t, 2, server[0].Header.PacketNumberLength)
	require.Nil(t, server[0].TLS)
	require.Equal(t, 2*(MaxCryptoBytes+MaxCryptoBytes/8), s.StateBytes())
	s.Close()
	require.Zero(t, s.StateBytes())
	require.Equal(t, Malformed, s.Feed(nil, Client)[0].Reason)
}

func putVarint(v uint64) []byte {
	if v < 64 {
		return []byte{byte(v)}
	}
	if v < 16384 {
		return []byte{0x40 | byte(v>>8), byte(v)}
	}
	if v < 1<<30 {
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	r := make([]byte, 8)
	binary.BigEndian.PutUint64(r, v)
	r[0] |= 0xc0
	return r
}
func cryptoFrame(offset uint64, data []byte) []byte {
	r := []byte{6}
	r = append(r, putVarint(offset)...)
	r = append(r, putVarint(uint64(len(data)))...)
	return append(r, data...)
}

// Controlled datagrams complement the independent RFC ciphertext vectors.
func protect(t testing.TB, plain []byte, pn uint32) []byte {
	t.Helper()
	k, err := keys([]byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}, Client)
	require.NoError(t, err)
	for len(plain) < 4 {
		plain = append(plain, 0)
	}
	header := []byte{0xc3, 0, 0, 0, 1, 8, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0, 0}
	header = append(header, putVarint(uint64(4+len(plain)+16))...)
	off := len(header)
	header = binary.BigEndian.AppendUint32(header, pn)
	nonce := append([]byte(nil), k.iv...)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	packet := k.aead.Seal(append([]byte(nil), header...), nonce, plain, header)
	var mask [16]byte
	k.hp.Encrypt(mask[:], packet[off+4:off+20])
	packet[0] ^= mask[0] & 15
	for i := 0; i < 4; i++ {
		packet[off+i] ^= mask[i+1]
	}
	return packet
}
func hello(t *testing.T) []byte {
	t.Helper()
	r := session(t).Feed(reference(t, "client"), Client)
	return r[0].ClientHello
}

func TestCryptoReassemblyOwnershipAndConflicts(t *testing.T) {
	h := hello(t)
	s := session(t)
	late := protect(t, cryptoFrame(100, h[100:]), 5)
	require.Equal(t, Incomplete, s.Feed(late, Client)[0].Reason)
	require.Equal(t, Incomplete, s.Feed(late, Client)[0].Reason, "retransmit is idempotent")
	r := s.Feed(protect(t, cryptoFrame(0, h[:120]), 4), Client)[0]
	require.Equal(t, Complete, r.Reason)
	require.Equal(t, h, r.ClientHello)
	// The result owns its recovered bytes across reuse/close.
	s.Close()
	require.Equal(t, h, r.ClientHello)
	s = session(t)
	require.Equal(t, Incomplete, s.Feed(protect(t, cryptoFrame(2, h[2:]), 1), Client)[0].Reason)
	bad := append([]byte(nil), h[2:6]...)
	bad[0] ^= 1
	require.Equal(t, ConflictingCrypto, s.Feed(protect(t, cryptoFrame(2, bad), 2), Client)[0].Reason)
	require.Equal(t, ConflictingCrypto, s.Feed(protect(t, cryptoFrame(0, h), 3), Client)[0].Reason)
}

func addExtension(h []byte, typ uint16, body []byte) []byte {
	h = append([]byte(nil), h...)
	pos := 39 + int(h[38])
	pos += 2 + int(binary.BigEndian.Uint16(h[pos:pos+2]))
	pos += 1 + int(h[pos])
	n := int(binary.BigEndian.Uint16(h[pos : pos+2]))
	binary.BigEndian.PutUint16(h[pos:pos+2], uint16(n+4+len(body)))
	h = binary.BigEndian.AppendUint16(h, typ)
	h = binary.BigEndian.AppendUint16(h, uint16(len(body)))
	h = append(h, body...)
	n = len(h) - 4
	h[1] = byte(n >> 16)
	h[2] = byte(n >> 8)
	h[3] = byte(n)
	return h
}
func TestECHAndTransportParameterFailures(t *testing.T) {
	h := addExtension(hello(t), 65037, []byte{0})
	r := session(t).Feed(protect(t, cryptoFrame(0, h), 0), Client)[0]
	require.Equal(t, ECHLimited, r.Reason)
	require.True(t, r.TLS.ECHOffered)
	require.NotEmpty(t, r.ClientHello)
	// Duplicate extension 57 is malformed, rather than silently overwriting evidence.
	h = addExtension(hello(t), 57, []byte{1, 0})
	require.Equal(t, Malformed, session(t).Feed(protect(t, cryptoFrame(0, h), 0), Client)[0].Reason)
	// Replace original TP extension contents with duplicate IDs at identical length.
	h = hello(t)
	at := bytes.Index(h, []byte{0, 57, 0, 50})
	require.Greater(t, at, 0)
	copy(h[at+4:at+54], bytes.Repeat([]byte{1, 0}, 25))
	require.Equal(t, Malformed, session(t).Feed(protect(t, cryptoFrame(0, h), 0), Client)[0].Reason)
}

func shape(version uint32, typ byte) []byte {
	h := []byte{0xc0 | typ<<4}
	h = binary.BigEndian.AppendUint32(h, version)
	h = append(h, 1, 7, 1, 8)
	if (version == Version1 && typ == 3) || (version == Version2 && typ == 0) {
		return append(h, make([]byte, 17)...)
	}
	if (version == Version1 && typ == 0) || (version == Version2 && typ == 1) {
		h = append(h, 2, 9, 10)
	}
	h = append(h, 20)
	return append(h, make([]byte, 20)...)
}
func TestVersionSpecificHeaderShapesAndCoalescing(t *testing.T) {
	for _, v := range []uint32{Version1, Version2} {
		for typ := byte(0); typ < 4; typ++ {
			h, r := Inspect(shape(v, typ))
			require.Len(t, h, 1)
			i := typ
			if v == Version2 {
				i = (typ + 3) & 3
			}
			require.Equal(t, []PacketType{Initial, ZeroRTT, Handshake, RetryPacket}[i], h[0].Type)
			require.Equal(t, "07", h[0].DCID)
			require.Equal(t, "08", h[0].SCID)
			if i == 3 {
				require.Equal(t, Retry, r)
			} else {
				require.Empty(t, r)
			}
			if i == 0 {
				require.Equal(t, uint64(2), h[0].TokenLength)
			}
			require.Zero(t, h[0].PacketNumberLength, "protected bits cannot reveal PN length")
		}
	}
	h, r := Inspect(append(shape(Version1, 0), shape(Version2, 2)...))
	require.Empty(t, r)
	require.Len(t, h, 2)
	raw := []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf}
	h, r = Inspect(raw)
	require.Equal(t, VersionNegotiation, r)
	require.Equal(t, []uint32{1, Version2}, h[0].Versions)
	raw[4] = 3
	_, r = Inspect(raw)
	require.Equal(t, UnsupportedVersion, r)
	s := session(t)
	r1 := s.Feed(append(reference(t, "client"), shape(Version1, 2)...), Client)
	require.Len(t, r1, 2)
	require.Equal(t, Complete, r1[0].Reason)
	require.Equal(t, UnsupportedPacket, r1[1].Reason)
	require.Equal(t, UnsupportedVersion, session(t).Feed(shape(Version2, 1), Client)[0].Reason)
	_, r = Inspect(append(shape(Version1, 0), 0x40, 0, 0))
	require.Equal(t, UnsupportedPacket, r, "short-header tail has no visible boundary")
}

func TestMalformedTruncatedAuthenticationAndBounds(t *testing.T) {
	packet := reference(t, "client")
	for i := 0; i < len(packet); i++ {
		s := session(t)
		r := s.Feed(packet[:i], Client)
		require.NotEqual(t, Complete, r[0].Reason)
		require.Zero(t, s.StateBytes())
		s.Close()
	}
	packet[len(packet)-1] ^= 1
	s := session(t)
	require.Equal(t, DecryptFailed, s.Feed(packet, Client)[0].Reason)
	require.Zero(t, s.StateBytes())
	for _, plain := range [][]byte{
		cryptoFrame(MaxCryptoBytes, []byte{1}),
		append([]byte{6}, putVarint(1<<62-1)...),
		{6, 0, 63, 1},         // declared fragment longer than packet
		{2, 0, 0, 0, 1},       // ACK first range exceeds largest
		{2, 0, 0, 1, 0, 0, 0}, // ACK gap underflows
	} {
		r := session(t).Feed(protect(t, plain, 0), Client)[0]
		require.Contains(t, []Reason{Malformed, ResourceLimit}, r.Reason)
	}
	require.Equal(t, ResourceLimit, session(t).Feed(protect(t, bytes.Repeat([]byte{1}, MaxFrames+1), 0), Client)[0].Reason)
	require.Equal(t, UnsupportedFrame, session(t).Feed(protect(t, []byte{8, 0, 0, 0}, 0), Client)[0].Reason)
	require.Equal(t, ResourceLimit, session(t).Feed(make([]byte, MaxDatagramBytes+1), Client)[0].Reason)
	s = session(t)
	for i := 0; i < MaxDatagrams; i++ {
		s.Feed(shape(Version2, 1), Client)
	}
	require.Equal(t, ResourceLimit, s.Feed(shape(Version2, 1), Client)[0].Reason)
	_, r := Inspect(bytes.Repeat(shape(Version1, 2), MaxPackets+1))
	require.Equal(t, ResourceLimit, r)
	_, err := NewSession(make([]byte, 21))
	require.Error(t, err)
	badCID := shape(Version1, 0)
	badCID[5] = 21
	_, r = Inspect(badCID)
	require.Equal(t, Malformed, r)
	vn := append([]byte{0x80, 0, 0, 0, 0, 0, 0}, make([]byte, 4*(MaxParameters+1))...)
	_, r = Inspect(vn)
	require.Equal(t, ResourceLimit, r)
	require.Equal(t, ResourceLimit, session(t).Feed(protect(t, cryptoFrame(0, []byte{1, 1, 0, 0}), 0), Client)[0].Reason)
}

func TestTransportParameterAvailabilityAndCountBound(t *testing.T) {
	h := hello(t)
	at := bytes.Index(h, []byte{0, 57, 0, 50})
	require.Greater(t, at, 0)
	h = h[:at] // The reference transport-parameter extension is last.
	pos := 39 + int(h[38])
	pos += 2 + int(binary.BigEndian.Uint16(h[pos:pos+2]))
	pos += 1 + int(h[pos])
	binary.BigEndian.PutUint16(h[pos:pos+2], uint16(len(h)-pos-2))
	n := len(h) - 4
	h[1], h[2], h[3] = byte(n>>16), byte(n>>8), byte(n)
	r := session(t).Feed(protect(t, cryptoFrame(0, h), 0), Client)[0]
	require.Equal(t, Complete, r.Reason)
	require.False(t, r.TransportParametersObserved)
	var body []byte
	for i := 0; i <= MaxParameters; i++ {
		body = append(body, putVarint(uint64(i))...)
		body = append(body, 0)
	}
	h = addExtension(h, 57, body)
	require.Equal(t, ResourceLimit, session(t).Feed(protect(t, cryptoFrame(0, h), 0), Client)[0].Reason)
}

func TestPacketNumberReconstruction(t *testing.T) {
	for _, tt := range []struct {
		pn, largest, want uint64
		have              bool
	}{{0, 255, 256, true}, {254, 256, 254, true}, {2, 0, 2, false}, {1, 65535, 65537, true}} {
		got, ok := reconstruct(tt.pn, 1, tt.largest, tt.have)
		require.True(t, ok)
		require.Equal(t, tt.want, got)
	}
}

func TestAuthenticatedFrameTypeRequiresMinimalEncoding(t *testing.T) {
	h := hello(t)
	for _, prefix := range [][]byte{{0x40, 6}, {0x80, 0, 0, 6}, {0xc0, 0, 0, 0, 0, 0, 0, 6}} {
		plain := append(append([]byte(nil), prefix...), cryptoFrame(0, h)[1:]...)
		s := session(t)
		r := s.Feed(protect(t, plain, 0), Client)[0]
		require.Equal(t, Malformed, r.Reason)
		require.Zero(t, s.StateBytes(), "invalid frame commits no CRYPTO")
	}
	// Offset and Length are allowed to use non-minimal varint representations.
	plain := []byte{6, 0x40, 0, 0x80, 0, 0, byte(len(h))}
	plain = append(plain, h...)
	require.Equal(t, Complete, session(t).Feed(protect(t, plain, 0), Client)[0].Reason)
}

func FuzzInitial(f *testing.F) {
	f.Add(reference(f, "client"))
	f.Add(reference(f, "server"))
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxDatagramBytes+1 {
			return
		}
		s := session(t)
		s.Feed(data, Client)
		Inspect(data)
	})
}

func BenchmarkReferenceInitial(b *testing.B) {
	packet := reference(b, "client")
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := NewSession(dcid)
		if err != nil {
			b.Fatal(err)
		}
		r := s.Feed(packet, Client)
		if r[0].Reason != Complete {
			b.Fatal(r)
		}
		s.Close()
	}
}

func TestGoQUICClientHello(t *testing.T) {
	client := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{ServerName: "quic-spike.example", NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}})
	defer func() {
		if err := client.Close(); err != nil {
			var alert tls.AlertError
			require.True(t, errors.As(err, &alert), "unfinished handshake shutdown: %v", err)
			require.Equal(t, tls.AlertError(0), alert, "expected close-notify on deliberate early shutdown")
		}
	}()
	client.SetTransportParameters([]byte{1, 1, 30, 4, 2, 0x44, 0xb0})
	require.NoError(t, client.Start(context.Background()))
	var handshake []byte
	for event := client.NextEvent(); event.Kind != tls.QUICNoEvent; event = client.NextEvent() {
		require.NotEqual(t, tls.QUICErrorEvent, event.Kind)
		if event.Kind == tls.QUICWriteData && event.Level == tls.QUICEncryptionLevelInitial {
			handshake = append(handshake, event.Data...)
		}
	}
	require.NotEmpty(t, handshake)
	s := session(t)
	split := len(handshake) / 2
	require.Equal(t, Incomplete, s.Feed(protect(t, cryptoFrame(uint64(split), handshake[split:]), 1), Client)[0].Reason)
	result := s.Feed(protect(t, cryptoFrame(0, handshake[:split]), 0), Client)[0]
	require.Equal(t, Complete, result.Reason)
	require.Equal(t, handshake, result.ClientHello)
	require.Equal(t, "quic-spike.example", result.TLS.SNI)
	require.Equal(t, []string{"h3"}, result.TLS.ALPNProtocols)
	require.Equal(t, []Parameter{{1, "1e"}, {4, "44b0"}}, result.Parameters)
	t.Logf("Go QUIC ClientHello recovered: %d bytes, %d transport parameters", len(handshake), len(result.Parameters))
}
