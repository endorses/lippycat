package capture

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func provenanceCapture(t *testing.T, link layers.LinkType, frames [][]byte, ng, compressed bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	var write func(gopacket.CaptureInfo, []byte) error
	var flush func() error
	if ng {
		w, err := pcapgo.NewNgWriter(&buf, link)
		require.NoError(t, err)
		write = w.WritePacket
		flush = w.Flush
	} else {
		w := pcapgo.NewWriterNanos(&buf)
		require.NoError(t, w.WriteFileHeader(65535, link))
		write = w.WritePacket
	}
	for i, data := range frames {
		require.NoError(t, write(gopacket.CaptureInfo{Timestamp: time.Unix(int64(100+i), 123456000).UTC(), CaptureLength: len(data), Length: len(data)}, data))
	}
	if flush != nil {
		require.NoError(t, flush())
	}
	if compressed {
		var out bytes.Buffer
		z := gzip.NewWriter(&out)
		_, err := z.Write(buf.Bytes())
		require.NoError(t, err)
		require.NoError(t, z.Close())
		return out.Bytes()
	}
	return buf.Bytes()
}

func TestOfflineBackingNormalizedReread(t *testing.T) {
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 4789}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	inner := buildESPNullIPv6Packet(42, buildMinimalTCPHeader(5060, 5060, []byte("INVITE sip:b@example.com SIP/2.0\r\n\r\n")), 6, 2, 12)
	outer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(outer, opts, ip, udp, &layers.VXLAN{ValidIDFlag: true, VNI: 42}, gopacket.Payload(inner)))
	outerBytes := append([]byte(nil), outer.Bytes()...)
	payload := outerBytes[20:]
	var fragments [][]byte
	for i, part := range [][]byte{payload[:32], payload[32:]} {
		f := *ip
		f.Id = 123
		f.FragOffset = uint16(i * 4)
		if i == 0 {
			f.Flags = layers.IPv4MoreFragments
		}
		b := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(b, opts, &f, gopacket.Payload(part)))
		fragments = append(fragments, append([]byte(nil), b.Bytes()...))
	}
	ipv6udp := make([]byte, 40)
	binary.BigEndian.PutUint16(ipv6udp[4:6], 40)
	v6frags := [][]byte{fragFrame(t, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 123, 0, true, ipv6udp[:16]), fragFrame(t, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 123, 2, false, ipv6udp[16:])}
	for _, tc := range []struct {
		name    string
		link    layers.LinkType
		frames  [][]byte
		derived bool
		filter  string
	}{
		{"unchanged", layers.LinkTypeEthernet, [][]byte{inner}, false, ""},
		{"vxlan", layers.LinkTypeRaw, [][]byte{outerBytes}, true, "udp dst port 4789"},
		{"ipv4-fragment-vxlan", layers.LinkTypeRaw, fragments, true, ""},
		{"ipv6-fragment", layers.LinkTypeEthernet, v6frags, true, ""},
		{"esp", layers.LinkTypeEthernet, [][]byte{inner}, true, ""},
		{"ipv4-fragment-vxlan-esp", layers.LinkTypeRaw, fragments, true, ""},
	} {
		for _, format := range []string{"pcap", "ng", "gzip"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "capture.data")
				require.NoError(t, os.WriteFile(path, provenanceCapture(t, tc.link, tc.frames, format == "ng", format == "gzip"), 0600))
				base := WithOfflineESPConfig(context.Background(), OfflineESPConfig{Enabled: tc.name == "esp" || tc.name == "ipv4-fragment-vxlan-esp", Explicit: true, ICVSize: 12})
				registry := sortTestStorage(t, 1<<20).NewBackingRegistry()
				t.Cleanup(func() { require.NoError(t, registry.Close()) })
				ctx := WithOfflineBackings(base, registry, offline.BackingSource)
				for index := uint32(0); index < 2; index++ {
					dev := offlineTestDevices(t, path)[0]
					legacy, err := newOfflineCursor(base, dev, tc.filter, index)
					require.NoError(t, err)
					c, err := newOfflineCursor(ctx, dev, tc.filter, index)
					require.NoError(t, err)
					want, err := legacy.Next(base)
					require.NoError(t, err)
					got, err := c.Next(ctx)
					require.NoError(t, err)
					require.Equal(t, want.Packet.Data(), got.Packet.Data())
					require.Equal(t, want.Packet.Metadata().CaptureInfo, got.Packet.Metadata().CaptureInfo)
					require.NotNil(t, got.Provenance)
					require.Equal(t, tc.derived, got.Provenance.Derived)
					require.Equal(t, index, got.Provenance.SourceIndex)
					require.Equal(t, uint64(len(tc.frames)-1), got.Provenance.PhysicalOrdinal)
					require.Zero(t, got.Provenance.LogicalSequence)
					require.Equal(t, tc.link, got.Provenance.OriginalLinkType)
					require.Equal(t, got.LinkType, got.Provenance.EffectiveLinkType)
					require.Equal(t, got.Packet.Metadata().CaptureInfo, got.Provenance.EffectiveCapture)
					_, err = c.Next(ctx)
					require.ErrorIs(t, err, io.EOF)
					require.NoError(t, c.Close())
					require.NoError(t, legacy.Close())
					lease, err := registry.Read(ctx, got.Provenance.Locator)
					require.NoError(t, err)
					require.Equal(t, want.Packet.Data(), lease.Bytes)
					require.NoError(t, lease.Close())
				}
			})
		}
	}
}

func TestOfflineBackingRejectsGzipNG(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture")
	require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, [][]byte{make([]byte, 60)}, true, true), 0600))
	r := sortTestStorage(t, 1<<20).NewBackingRegistry()
	defer func() { require.NoError(t, r.Close()) }()
	_, err := newOfflineCursor(WithOfflineBackings(context.Background(), r, offline.BackingSource), offlineTestDevices(t, path)[0], "", 0)
	require.ErrorContains(t, err, "unrecognized PCAP magic")
}

func TestOfflineBackingBPFPhysicalSequence(t *testing.T) {
	raw := make([]byte, 60)
	copy(raw, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0, 0x45, 0, 0, 46, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0x27, 0x10, 0x4e, 0x20, 0, 26, 0, 0})
	accepted := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(accepted[36:38], 5060)
	path := filepath.Join(t.TempDir(), "capture")
	require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, [][]byte{raw, accepted, raw, accepted}, false, false), 0600))
	r := sortTestStorage(t, 1<<20).NewBackingRegistry()
	defer func() { require.NoError(t, r.Close()) }()
	ctx := WithOfflineBackings(context.Background(), r, offline.BackingSource)
	for _, filter := range []string{"udp dst port 5060", "udp dst port 1"} {
		c, err := newOfflineCursor(ctx, offlineTestDevices(t, path)[0], filter, 0)
		require.NoError(t, err)
		if filter == "udp dst port 5060" {
			for i := 0; i < 2; i++ {
				p, err := c.Next(ctx)
				require.NoError(t, err)
				require.Equal(t, uint64(i), p.Provenance.LogicalSequence)
				require.Equal(t, uint64(2*i+1), p.Provenance.PhysicalOrdinal)
			}
		}
		_, err = c.Next(ctx)
		require.ErrorIs(t, err, io.EOF)
		require.NoError(t, c.Close())
	}
}
