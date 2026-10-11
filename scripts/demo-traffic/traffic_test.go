package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestCaptureDeterminismAndPacing(t *testing.T) {
	directory := t.TempDir()
	first, second := filepath.Join(directory, "first.pcap"), filepath.Join(directory, "second.pcap")
	for _, path := range []string{first, second} {
		count, err := writeCapture(context.Background(), path, 10*time.Second, 30)
		if err != nil || count != 300 {
			t.Fatalf("generate capture: count=%d err=%v", count, err)
		}
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("identical settings produced different capture bytes")
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	if reader.LinkType() != layers.LinkTypeEthernet {
		t.Fatalf("unexpected link type: %v", reader.LinkType())
	}
	for index := int64(0); index < 300; index++ {
		data, info, err := reader.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		// At 30 pps, each whole second must land exactly on its boundary.
		want := captureStart.Add(time.Duration(index/30)*time.Second + time.Duration(index%30)*time.Second/30).Truncate(time.Microsecond)
		if !info.Timestamp.Equal(want) || info.Length != len(data) || info.CaptureLength != len(data) {
			t.Fatalf("invalid record %d: %+v; expected %v, %d bytes", index, info, want, len(data))
		}
	}
	if _, _, err := reader.ReadPacketData(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected end of capture, got %v", err)
	}
}

func TestGeneratedWireAndProtocolCoverage(t *testing.T) {
	protocols := detector.NewWithDefaultSignatures()
	defer protocols.Shutdown()
	histogram := map[string]int{}
	for _, cycle := range []int{0, 1, 250} {
		frames, err := buildCycle(cycle)
		if err != nil {
			t.Fatal(err)
		}
		for index, data := range frames {
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			if decodeErr := packet.ErrorLayer(); decodeErr != nil {
				t.Fatalf("cycle %d frame %d cannot decode: %v", cycle, index, decodeErr.Error())
			}
			checkChecksums(t, packet)
			name := ""
			if packet.Layer(layers.LayerTypeICMPv6) != nil {
				name = "ICMPv6"
			} else if transport := packet.TransportLayer(); transport != nil {
				name = transport.LayerType().String()
			}
			if result := protocols.Detect(packet); result != nil && result.Protocol != "unknown" {
				name = result.Protocol
			}
			if name != "" {
				histogram[name]++
			}
		}
		checkTCPExchanges(t, frames)
	}
	for _, protocol := range []string{"ARP", "ICMP", "ICMPv6", "TCP", "UDP", "DNS", "SIP", "RTP", "HTTP", "TLS", "SSH", "WireGuard", "SMTP", "IMAP", "POP3", "DHCP", "NTP", "RADIUS"} {
		if histogram[protocol] == 0 {
			t.Errorf("lippycat did not recognize generated %s packets", protocol)
		}
	}
	t.Logf("actual lippycat detector histogram: %v", histogram)
}

func checkChecksums(t *testing.T, packet gopacket.Packet) {
	t.Helper()
	var pseudo []byte
	var protocol byte
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip := layer.(*layers.IPv4)
		if sum(ip.Contents) != 0xffff || int(ip.Length) != len(ip.Contents)+len(ip.Payload) {
			t.Fatal("invalid IPv4 checksum or total length")
		}
		protocol = byte(ip.Protocol)
		pseudo = append(append(pseudo, ip.SrcIP...), ip.DstIP...)
		pseudo = append(pseudo, 0, protocol)
		pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(ip.Payload)))
	} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ip := layer.(*layers.IPv6)
		if int(ip.Length) != len(ip.Payload) {
			t.Fatal("invalid IPv6 payload length")
		}
		protocol = byte(ip.NextHeader)
		pseudo = append(append(pseudo, ip.SrcIP...), ip.DstIP...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(ip.Payload)))
		pseudo = append(pseudo, 0, 0, 0, protocol)
	} else {
		return
	}
	if protocol == byte(layers.IPProtocolICMPv4) {
		icmp := packet.Layer(layers.LayerTypeICMPv4)
		if icmp == nil || sum(append(append([]byte{}, icmp.LayerContents()...), icmp.LayerPayload()...)) != 0xffff {
			t.Fatal("invalid ICMPv4 checksum")
		}
		return
	}
	if protocol != byte(layers.IPProtocolTCP) && protocol != byte(layers.IPProtocolUDP) && protocol != byte(layers.IPProtocolICMPv6) {
		return
	}
	var transport gopacket.Layer
	if protocol == byte(layers.IPProtocolICMPv6) {
		transport = packet.Layer(layers.LayerTypeICMPv6)
	} else {
		transport = packet.TransportLayer()
	}
	if transport == nil {
		t.Fatal("missing transport layer")
	}
	if udp, ok := transport.(*layers.UDP); ok && int(udp.Length) != len(udp.Contents)+len(udp.Payload) {
		t.Fatal("invalid UDP datagram length")
	}
	checked := append(append(pseudo, transport.LayerContents()...), transport.LayerPayload()...)
	if sum(checked) != 0xffff {
		t.Fatalf("invalid %s pseudoheader checksum", transport.LayerType())
	}
}

func sum(data []byte) uint16 {
	var result uint32
	for len(data) >= 2 {
		result += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		result += uint32(data[0]) << 8
	}
	for result>>16 != 0 {
		result = (result & 0xffff) + result>>16
	}
	return uint16(result)
}

func checkTCPExchanges(t *testing.T, frames [][]byte) {
	t.Helper()
	type state struct {
		next uint32
		fin  bool
	}
	flows := map[string]state{}
	for _, data := range frames {
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		layer := packet.Layer(layers.LayerTypeTCP)
		if layer == nil {
			continue
		}
		tcp := layer.(*layers.TCP)
		source, destination := packet.NetworkLayer().NetworkFlow().Endpoints()
		key := source.String() + ":" + tcp.SrcPort.String() + "->" + destination.String() + ":" + tcp.DstPort.String()
		peer := destination.String() + ":" + tcp.DstPort.String() + "->" + source.String() + ":" + tcp.SrcPort.String()
		current, started := flows[key]
		if !started && !tcp.SYN {
			t.Fatalf("TCP stream did not start with SYN: %s", key)
		}
		if started && tcp.Seq != current.next {
			t.Fatalf("out-of-order TCP sequence on %s: got %d want %d", key, tcp.Seq, current.next)
		}
		if other, ok := flows[peer]; tcp.ACK && (!ok || tcp.Ack != other.next) {
			t.Fatalf("invalid TCP acknowledgment on %s: got %d want %+v", key, tcp.Ack, other)
		}
		current.next = tcp.Seq + uint32(len(tcp.Payload))
		if tcp.SYN || tcp.FIN {
			current.next++
		}
		current.fin = current.fin || tcp.FIN
		flows[key] = current
	}
	if len(flows) == 0 {
		t.Fatal("no TCP streams")
	}
	for key, flow := range flows {
		if !flow.fin {
			t.Errorf("TCP direction did not close: %s", key)
		}
	}
}

func TestInvalidSettingsAndCancellationPreserveDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.pcap")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, settings := range []struct {
		duration time.Duration
		pps      int
	}{{0, 30}, {time.Second, 0}, {time.Second, 1_000_001}} {
		if _, err := writeCapture(context.Background(), path, settings.duration, settings.pps); err == nil {
			t.Fatal("invalid settings accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writeCapture(ctx, path, time.Second, 30); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing" {
		t.Fatalf("existing destination changed on failure: %q %v", data, err)
	}
}
