package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func offlineDecoderFixture(t testing.TB, ipv6, tcp bool, port uint16, options []layers.TCPOption, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	protocol := layers.IPProtocolUDP
	if tcp {
		protocol = layers.IPProtocolTCP
	}
	var network gopacket.NetworkLayer
	var serial gopacket.SerializableLayer
	if ipv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, NextHeader: protocol, HopLimit: 64, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
		network, serial = ip, ip
	} else {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: protocol, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
		network, serial = ip, ip
	}
	var transport gopacket.SerializableLayer
	if tcp {
		tcp := &layers.TCP{SrcPort: 40000, DstPort: layers.TCPPort(port), Seq: 123, Ack: 456, ACK: true, Window: 4096, Options: options}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(network))
		transport = tcp
	} else {
		udp := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(port)}
		require.NoError(t, udp.SetNetworkLayerForChecksum(network))
		transport = udp
	}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, serial, transport, gopacket.Payload(payload)))
	return append([]byte(nil), buffer.Bytes()...)
}

func requireOfflinePacketParity(t *testing.T, raw []byte, link layers.LinkType, got gopacket.Packet) {
	t.Helper()
	want := gopacket.NewPacket(raw, link, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(100, 200), CaptureLength: len(raw), Length: len(raw) + 5, InterfaceIndex: 7}
	want.Metadata().CaptureInfo, got.Metadata().CaptureInfo = ci, ci
	require.Equal(t, want.Data(), got.Data())
	require.Equal(t, want.Metadata(), got.Metadata())
	require.Equal(t, want.String(), got.String())
	require.Equal(t, want.Dump(), got.Dump())
	require.Len(t, got.Layers(), len(want.Layers()))
	for i, expected := range want.Layers() {
		actual := got.Layers()[i]
		require.IsType(t, expected, actual)
		require.Equal(t, expected.LayerType(), actual.LayerType())
		require.Equal(t, expected.LayerContents(), actual.LayerContents())
		require.Equal(t, expected.LayerPayload(), actual.LayerPayload())
		// Compare all exported layer fields, including TCP options and padding;
		// internal option storage is deliberately reused instead of allocated.
		if expected.LayerType() != gopacket.LayerTypeDecodeFailure {
			wantFields, err := json.Marshal(expected)
			require.NoError(t, err)
			gotFields, err := json.Marshal(actual)
			require.NoError(t, err)
			require.Equal(t, string(wantFields), string(gotFields))
		}
		require.Equal(t, actual, got.Layer(expected.LayerType()))
		require.Equal(t, actual, got.LayerClass(expected.LayerType()))
	}
	require.Nil(t, got.Layer(gopacket.LayerTypeZero))
	require.Nil(t, got.LayerClass(gopacket.LayerTypeZero))
	if want.LinkLayer() == nil {
		require.Nil(t, got.LinkLayer())
	} else {
		require.Equal(t, want.LinkLayer().LinkFlow(), got.LinkLayer().LinkFlow())
	}
	if want.NetworkLayer() == nil {
		require.Nil(t, got.NetworkLayer())
	} else {
		require.Equal(t, want.NetworkLayer().NetworkFlow(), got.NetworkLayer().NetworkFlow())
	}
	if want.TransportLayer() == nil {
		require.Nil(t, got.TransportLayer())
	} else {
		require.Equal(t, want.TransportLayer().TransportFlow(), got.TransportLayer().TransportFlow())
	}
	if want.ApplicationLayer() == nil {
		require.Nil(t, got.ApplicationLayer())
	} else {
		require.Equal(t, want.ApplicationLayer().Payload(), got.ApplicationLayer().Payload())
	}
	if want.ErrorLayer() == nil {
		require.Nil(t, got.ErrorLayer())
	} else {
		require.EqualError(t, got.ErrorLayer().Error(), want.ErrorLayer().Error().Error())
	}
}

func TestOfflinePacketDecoderDifferentialAndReuse(t *testing.T) {
	var decoder offlinePacketDecoder
	optionSets := [][]layers.TCPOption{
		nil,
		{{OptionType: layers.TCPOptionKindNop}, {OptionType: layers.TCPOptionKindNop}, {OptionType: layers.TCPOptionKindTimestamps, OptionData: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
		{{OptionType: layers.TCPOptionKindMSS, OptionData: []byte{5, 180}}, {OptionType: layers.TCPOptionKindEndList}},
	}
	for round := range 2 {
		for _, ipv6 := range []bool{false, true} {
			for _, tcp := range []bool{false, true} {
				for index, options := range optionSets {
					for _, payload := range [][]byte{nil, []byte("payload to retain until callback returns")} {
						t.Run(fmt.Sprintf("round%d/ipv6=%t/tcp=%t/options=%d/payload=%d", round, ipv6, tcp, index, len(payload)), func(t *testing.T) {
							raw := offlineDecoderFixture(t, ipv6, tcp, 40001, options, payload)
							packet := decoder.decode(raw, layers.LinkTypeEthernet)
							require.Same(t, &decoder, packet)
							requireOfflinePacketParity(t, raw, layers.LinkTypeEthernet, packet)
						})
					}
				}
			}
		}
	}
}

func TestOfflinePacketDecoderFallbacks(t *testing.T) {
	var decoder offlinePacketDecoder
	for _, tcp := range []bool{false, true} {
		raw := offlineDecoderFixture(t, false, tcp, 53, nil, []byte("not a valid DNS message"))
		packet := decoder.decode(raw, layers.LinkTypeEthernet)
		require.NotSame(t, &decoder, packet, "application decoders retain standard path")
		requireOfflinePacketParity(t, raw, layers.LinkTypeEthernet, packet)
	}
	raw := offlineDecoderFixture(t, false, true, 40001, nil, []byte("payload"))
	for length := 0; length < len(raw)-1; length++ {
		part := raw[:length]
		requireOfflinePacketParity(t, part, layers.LinkTypeEthernet, decoder.decode(part, layers.LinkTypeEthernet))
	}
	for _, offset := range []int{14, 20, 21, 26, 46} {
		mutated := append([]byte(nil), raw...)
		mutated[offset] = 0xff
		requireOfflinePacketParity(t, mutated, layers.LinkTypeEthernet, decoder.decode(mutated, layers.LinkTypeEthernet))
	}
	requireOfflinePacketParity(t, raw[14:], layers.LinkTypeRaw, decoder.decode(raw[14:], layers.LinkTypeRaw))
	// A fallback must not expose stale layers from the preceding fast packet.
	requireOfflinePacketParity(t, raw, layers.LinkTypeEthernet, decoder.decode(raw, layers.LinkTypeEthernet))
}

func TestOfflinePacketDecoderTLSAndEmptyApplicationPorts(t *testing.T) {
	var decoder offlinePacketDecoder
	records := [][]byte{
		{20, 3, 3, 0, 1, 1},
		{21, 3, 3, 0, 2, 1, 0},
		{22, 3, 3, 0, 4, 1, 0, 0, 0},
		{23, 3, 3, 0, 3, 7, 8, 9},
	}
	var multi []byte
	for _, record := range records {
		multi = append(multi, record...)
	}
	for _, ipv6 := range []bool{false, true} {
		for _, payload := range append(records, multi, nil, records[0], records[3]) {
			raw := offlineDecoderFixture(t, ipv6, true, 443, nil, payload)
			packet := decoder.decode(raw, layers.LinkTypeEthernet)
			require.Same(t, &decoder, packet)
			requireOfflinePacketParity(t, raw, layers.LinkTypeEthernet, packet)
		}
		for index, payload := range [][]byte{
			{23, 3, 3, 0, 10, 1},        // incomplete record
			{20, 3, 3, 0, 0},            // invalid change-cipher-spec
			{21, 3, 3, 0, 1, 1},         // invalid alert
			bytes.Repeat(records[3], 9), // exceed reusable storage
		} {
			raw := offlineDecoderFixture(t, ipv6, true, 443, nil, payload)
			packet := decoder.decode(raw, layers.LinkTypeEthernet)
			if index < 3 {
				require.Same(t, &decoder, packet)
				require.IsType(t, &gopacket.DecodeFailure{}, packet.ErrorLayer())
			} else {
				require.NotSame(t, &decoder, packet)
			}
			requireOfflinePacketParity(t, raw, layers.LinkTypeEthernet, packet)
		}
		for _, tcp := range []bool{false, true} {
			raw := offlineDecoderFixture(t, ipv6, tcp, 53, nil, nil)
			packet := decoder.decode(raw, layers.LinkTypeEthernet)
			require.Same(t, &decoder, packet)
			requireOfflinePacketParity(t, raw, layers.LinkTypeEthernet, packet)
		}
	}
}

func TestOfflinePacketDecoderPartialTLSKeepsStandardFailure(t *testing.T) {
	var decoder offlinePacketDecoder
	for _, ipv6 := range []bool{false, true} {
		for _, payload := range [][]byte{
			{0xff, 1, 2, 3, 4, 5},
			{23, 3},
			{23, 3, 3, 0, 9, 1, 2},
			{23, 3, 3, 0, 1, 1, 0xff, 1, 2, 3, 4},
			{23, 3, 3, 0, 1, 1, 23, 3},
		} {
			raw := offlineDecoderFixture(t, ipv6, true, 443, nil, payload)
			packet := decoder.decode(raw, layers.LinkTypeEthernet)
			require.Same(t, &decoder, packet)
			require.IsType(t, &gopacket.DecodeFailure{}, packet.ErrorLayer())
			require.Nil(t, packet.ApplicationLayer())
			requireOfflinePacketParity(t, raw, layers.LinkTypeEthernet, packet)
			// A later plain packet must release the previous temporary packet
			// and expose neither its failure nor truncation state.
			plain := offlineDecoderFixture(t, ipv6, false, 40001, nil, []byte("plain"))
			packet = decoder.decode(plain, layers.LinkTypeEthernet)
			require.Nil(t, decoder.applicationPacket)
			requireOfflinePacketParity(t, plain, layers.LinkTypeEthernet, packet)
		}
	}
}

func TestOfflineReusablePacketVisitorAndObserverOwnership(t *testing.T) {
	frames := make([][]byte, 70) // Cross replay's backing lease boundary.
	for i := range frames {
		frames[i] = offlineDecoderFixture(t, i%2 == 0, i%3 == 0, 40001, nil, []byte(fmt.Sprintf("packet-%d", i)))
	}
	path := filepath.Join(t.TempDir(), "source.pcap")
	require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, frames, false, false), 0600))
	storage := sortTestStorage(t, 64<<10)
	stream, err := PrepareOfflineLocatorStream(context.Background(), offlineTestDevices(t, path), "", storage, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, stream.Close()) }()
	var borrowed *offlinePacketDecoder
	var retained []PacketInfo
	restore := SetPacketObserver(func(info *PacketInfo) {
		require.NotSame(t, borrowed, info.Packet)
		retained = append(retained, *info)
	})
	defer restore()
	visited := 0
	require.NoError(t, stream.ReplayPackets(context.Background(), func(_ context.Context, info PacketInfo) error {
		decoder, ok := info.Packet.(*offlinePacketDecoder)
		require.True(t, ok)
		if borrowed != nil {
			require.Same(t, borrowed, decoder)
		}
		borrowed = decoder
		require.Equal(t, frames[visited], info.Packet.Data())
		require.Equal(t, info.Provenance.EffectiveCapture, info.Packet.Metadata().CaptureInfo)
		visited++
		return nil
	}))
	require.NoError(t, stream.Close())
	require.Equal(t, len(frames), visited)
	require.Len(t, retained, len(frames))
	for i, info := range retained {
		require.Equal(t, frames[i], info.Packet.Data())
		require.EqualValues(t, i, info.SourceSequence)
		require.Equal(t, info.Provenance.EffectiveCapture, info.Packet.Metadata().CaptureInfo)
		want := gopacket.NewPacket(frames[i], layers.LinkTypeEthernet, gopacket.NoCopy)
		require.Equal(t, want.TransportLayer().TransportFlow(), info.Packet.TransportLayer().TransportFlow())
	}
}

func BenchmarkOfflinePacketDecoder(b *testing.B) {
	raw := offlineDecoderFixture(b, false, true, 40001, []layers.TCPOption{{OptionType: layers.TCPOptionKindTimestamps, OptionData: []byte{1, 2, 3, 4, 5, 6, 7, 8}}}, make([]byte, 1400))
	for _, reuse := range []bool{false, true} {
		b.Run(fmt.Sprintf("reuse=%t", reuse), func(b *testing.B) {
			var decoder offlinePacketDecoder
			b.ReportAllocs()
			for range b.N {
				var packet gopacket.Packet
				if reuse {
					packet = decoder.decode(raw, layers.LinkTypeEthernet)
				} else {
					packet = gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
				}
				if packet.TransportLayer() == nil {
					b.Fatal("no transport")
				}
			}
		})
	}
}

func TestOfflinePacketDecoderPrivateCoverage(t *testing.T) {
	path := os.Getenv("LIPPYCAT_BENCH_PCAP")
	if path == "" {
		t.Skip("set LIPPYCAT_BENCH_PCAP for private coverage")
	}
	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	counts := map[string]int{}
	var decoder offlinePacketDecoder
	for {
		raw, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		packet := decoder.decode(raw, reader.LinkType())
		counts["total"]++
		if packet == &decoder {
			counts["reused"]++
			continue
		}
		if ethernet, ok := packet.LinkLayer().(*layers.Ethernet); ok {
			counts["ether_"+ethernet.EthernetType.String()]++
		}
		if ip, ok := packet.NetworkLayer().(*layers.IPv4); ok && ip.IHL != 5 {
			counts["ipv4_options"]++
		}
		if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
			if len(tcp.Payload) == 0 {
				counts["tcp_empty_payload"]++
			}
			counts["tcp_next_"+tcp.NextLayerType().String()]++
			if tcp.NextLayerType() == layers.LayerTypeTLS {
				if packet.ErrorLayer() != nil {
					counts["tls_error_"+packet.ErrorLayer().Error().Error()]++
				} else {
					counts["tls_complete"]++
				}
			}
		} else if udp, ok := packet.TransportLayer().(*layers.UDP); ok {
			counts["udp_next_"+udp.NextLayerType().String()]++
		} else {
			counts["other"]++
		}
	}
	t.Logf("decoder coverage: %v", counts)
}

func TestOfflinePacketDecoderPrivateParity(t *testing.T) {
	path := os.Getenv("LIPPYCAT_BENCH_PCAP")
	if path == "" {
		t.Skip("set LIPPYCAT_BENCH_PCAP for private packet parity")
	}
	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	decoder := NewOfflinePacketDecoder()
	fields := map[reflect.Type][]int{}
	count := 0
	for {
		raw, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		want := gopacket.NewPacket(raw, reader.LinkType(), gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
		got := decoder.Decode(raw, reader.LinkType())
		want.Metadata().CaptureInfo, got.Metadata().CaptureInfo = ci, ci
		if !reflect.DeepEqual(want.Metadata(), got.Metadata()) || len(want.Layers()) != len(got.Layers()) {
			t.Fatalf("packet %d metadata/layer count differ", count)
		}
		for index, expected := range want.Layers() {
			actual := got.Layers()[index]
			if reflect.TypeOf(expected) != reflect.TypeOf(actual) || expected.LayerType() != actual.LayerType() || !bytes.Equal(expected.LayerContents(), actual.LayerContents()) || !bytes.Equal(expected.LayerPayload(), actual.LayerPayload()) {
				t.Fatalf("packet %d layer %d type/bytes differ", count, index)
			}
			if expected.LayerType() == gopacket.LayerTypeDecodeFailure {
				if want.ErrorLayer().Error().Error() != got.ErrorLayer().Error().Error() {
					t.Fatalf("packet %d decode error differs", count)
				}
				continue
			}
			left, right := reflect.ValueOf(expected), reflect.ValueOf(actual)
			if left.Kind() == reflect.Pointer {
				left, right = left.Elem(), right.Elem()
			}
			if left.Kind() != reflect.Struct {
				if !reflect.DeepEqual(left.Interface(), right.Interface()) {
					t.Fatalf("packet %d layer %d differs", count, index)
				}
				continue
			}
			typ := left.Type()
			indices, exists := fields[typ]
			if !exists {
				for i := range typ.NumField() {
					if typ.Field(i).PkgPath == "" {
						indices = append(indices, i)
					}
				}
				fields[typ] = indices
			}
			for _, field := range indices {
				if !reflect.DeepEqual(left.Field(field).Interface(), right.Field(field).Interface()) {
					t.Fatalf("packet %d layer %d field %s differs", count, index, typ.Field(field).Name)
				}
			}
		}
		count++
	}
	t.Logf("all %d physical packets match standard concrete layers, exported fields, bytes, errors and metadata; fixed decoder bytes=%d", count, decoder.MemoryBytes())
}
