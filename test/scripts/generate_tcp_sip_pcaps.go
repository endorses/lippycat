// Generate TCP SIP test PCAP files for integration testing
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	fmt.Println("Generating TCP SIP test PCAP files...")
	fmt.Println()

	if err := generateCompleteTCPCall(); err != nil {
		log.Fatalf("Failed to generate complete call: %v", err)
	}

	if err := generateFailedTCPCall(); err != nil {
		log.Fatalf("Failed to generate failed call: %v", err)
	}

	if err := generatePAssertedIdentityCall(); err != nil {
		log.Fatalf("Failed to generate P-Asserted-Identity call: %v", err)
	}

	if err := generateMultistreamCall(); err != nil {
		log.Fatalf("Failed to generate multistream call: %v", err)
	}

	fmt.Println()
	fmt.Println("✓ All TCP SIP test PCAPs generated successfully!")
	fmt.Println()
	fmt.Println("Test files:")
	fmt.Println("  - tcp_sip_complete_call.pcap: Full call flow (INVITE→200→ACK→BYE→200)")
	fmt.Println("  - tcp_sip_failed_call.pcap: Failed call (INVITE→486 Busy)")
	fmt.Println("  - tcp_sip_passerted_identity.pcap: Call with P-Asserted-Identity")
	fmt.Println("  - tcp_sip_multistream.pcap: Conference call with 3 audio streams")
}

func createPCAPWriter(filename string) (*os.File, *pcapgo.Writer, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, nil, err
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return nil, nil, err
	}

	return f, w, nil
}

func writeTCPHandshake(w *pcapgo.Writer, srcIP, dstIP string, srcPort, dstPort uint16, seqBase uint32) (uint32, uint32, error) {
	ts := time.Now()

	// SYN
	syn := createTCPPacket(srcIP, dstIP, srcPort, dstPort, seqBase, 0, "S", nil)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(syn), Length: len(syn)}, syn); err != nil {
		return 0, 0, err
	}

	// SYN-ACK
	ts = ts.Add(time.Millisecond)
	synack := createTCPPacket(dstIP, srcIP, dstPort, srcPort, seqBase+1000, seqBase+1, "SA", nil)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(synack), Length: len(synack)}, synack); err != nil {
		return 0, 0, err
	}

	// ACK
	ts = ts.Add(time.Millisecond)
	ack := createTCPPacket(srcIP, dstIP, srcPort, dstPort, seqBase+1, seqBase+1001, "A", nil)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(ack), Length: len(ack)}, ack); err != nil {
		return 0, 0, err
	}

	return seqBase + 1, seqBase + 1001, nil
}

func createTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags string, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte(parseIP(srcIP)),
		DstIP:    []byte(parseIP(dstIP)),
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		Window:  5840,
	}

	// Set flags
	for _, f := range flags {
		switch f {
		case 'S':
			tcp.SYN = true
		case 'A':
			tcp.ACK = true
		case 'P':
			tcp.PSH = true
		case 'F':
			tcp.FIN = true
		}
	}

	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true}

	if payload != nil {
		gopacket.SerializeLayers(buffer, opts, eth, ip, tcp, gopacket.Payload(payload))
	} else {
		gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
	}

	return buffer.Bytes()
}

func parseIP(ip string) []byte {
	var result [4]byte
	fmt.Sscanf(ip, "%d.%d.%d.%d", &result[0], &result[1], &result[2], &result[3])
	return result[:]
}

func generateCompleteTCPCall() error {
	f, w, err := createPCAPWriter("testdata/pcaps/tcp_sip_complete_call.pcap")
	if err != nil {
		return err
	}
	defer f.Close()

	srcSeq, dstSeq, err := writeTCPHandshake(w, "192.168.1.100", "192.168.1.101", 50000, 5060, 10000)
	if err != nil {
		return err
	}

	ts := time.Now().Add(5 * time.Millisecond)

	// INVITE with SDP
	invite := `INVITE sip:bob@192.168.1.101 SIP/2.0
Via: SIP/2.0/TCP 192.168.1.100:50000;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Bob <sip:bob@192.168.1.101>
From: Alice <sip:alice@192.168.1.100>;tag=1928301774
Call-ID: tcp-complete-call-12345@192.168.1.100
CSeq: 314159 INVITE
Contact: <sip:alice@192.168.1.100:50000;transport=tcp>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alice 53655765 2353687637 IN IP4 192.168.1.100
s=Session SDP
c=IN IP4 192.168.1.100
t=0 0
m=audio 8000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
`

	pkt := createTCPPacket("192.168.1.100", "192.168.1.101", 50000, 5060, srcSeq, dstSeq, "PA", []byte(invite))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}
	srcSeq += uint32(len(invite))
	ts = ts.Add(time.Millisecond)

	// ACK from Bob
	ack := createTCPPacket("192.168.1.101", "192.168.1.100", 5060, 50000, dstSeq, srcSeq, "A", nil)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(ack), Length: len(ack)}, ack); err != nil {
		return err
	}
	ts = ts.Add(time.Millisecond)

	// 200 OK with SDP
	ok := `SIP/2.0 200 OK
Via: SIP/2.0/TCP 192.168.1.100:50000;branch=z9hG4bK776asdhds
To: Bob <sip:bob@192.168.1.101>;tag=a6c85cf
From: Alice <sip:alice@192.168.1.100>;tag=1928301774
Call-ID: tcp-complete-call-12345@192.168.1.100
CSeq: 314159 INVITE
Contact: <sip:bob@192.168.1.101:5060;transport=tcp>
Content-Type: application/sdp
Content-Length: 138

v=0
o=bob 53655765 2353687638 IN IP4 192.168.1.101
s=Session SDP
c=IN IP4 192.168.1.101
t=0 0
m=audio 8002 RTP/AVP 0
a=rtpmap:0 PCMU/8000
`

	pkt = createTCPPacket("192.168.1.101", "192.168.1.100", 5060, 50000, dstSeq, srcSeq, "PA", []byte(ok))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}
	dstSeq += uint32(len(ok))
	ts = ts.Add(time.Millisecond)

	// ACK from Alice
	ack = createTCPPacket("192.168.1.100", "192.168.1.101", 50000, 5060, srcSeq, dstSeq, "A", nil)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(ack), Length: len(ack)}, ack); err != nil {
		return err
	}
	ts = ts.Add(time.Millisecond)

	// ACK (confirming 200 OK)
	ackSip := `ACK sip:bob@192.168.1.101:5060 SIP/2.0
Via: SIP/2.0/TCP 192.168.1.100:50000;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Bob <sip:bob@192.168.1.101>;tag=a6c85cf
From: Alice <sip:alice@192.168.1.100>;tag=1928301774
Call-ID: tcp-complete-call-12345@192.168.1.100
CSeq: 314159 ACK
Content-Length: 0

`

	pkt = createTCPPacket("192.168.1.100", "192.168.1.101", 50000, 5060, srcSeq, dstSeq, "PA", []byte(ackSip))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}
	srcSeq += uint32(len(ackSip))
	ts = ts.Add(time.Millisecond)

	// BYE
	bye := `BYE sip:bob@192.168.1.101:5060 SIP/2.0
Via: SIP/2.0/TCP 192.168.1.100:50000;branch=z9hG4bK776bye
Max-Forwards: 70
To: Bob <sip:bob@192.168.1.101>;tag=a6c85cf
From: Alice <sip:alice@192.168.1.100>;tag=1928301774
Call-ID: tcp-complete-call-12345@192.168.1.100
CSeq: 314160 BYE
Content-Length: 0

`

	pkt = createTCPPacket("192.168.1.100", "192.168.1.101", 50000, 5060, srcSeq, dstSeq, "PA", []byte(bye))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}
	srcSeq += uint32(len(bye))
	ts = ts.Add(time.Millisecond)

	// 200 OK (BYE response)
	okBye := `SIP/2.0 200 OK
Via: SIP/2.0/TCP 192.168.1.100:50000;branch=z9hG4bK776bye
To: Bob <sip:bob@192.168.1.101>;tag=a6c85cf
From: Alice <sip:alice@192.168.1.100>;tag=1928301774
Call-ID: tcp-complete-call-12345@192.168.1.100
CSeq: 314160 BYE
Content-Length: 0

`

	pkt = createTCPPacket("192.168.1.101", "192.168.1.100", 5060, 50000, dstSeq, srcSeq, "PA", []byte(okBye))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}

	fmt.Println("✓ Generated tcp_sip_complete_call.pcap")
	return nil
}

func generateFailedTCPCall() error {
	f, w, err := createPCAPWriter("testdata/pcaps/tcp_sip_failed_call.pcap")
	if err != nil {
		return err
	}
	defer f.Close()

	srcSeq, dstSeq, err := writeTCPHandshake(w, "192.168.1.100", "192.168.1.101", 50001, 5060, 20000)
	if err != nil {
		return err
	}

	ts := time.Now().Add(5 * time.Millisecond)

	// INVITE
	invite := `INVITE sip:bob@192.168.1.101 SIP/2.0
Via: SIP/2.0/TCP 192.168.1.100:50001;branch=z9hG4bK123failed
Max-Forwards: 70
To: Bob <sip:bob@192.168.1.101>
From: Alice <sip:alice@192.168.1.100>;tag=failed123
Call-ID: tcp-failed-call-99999@192.168.1.100
CSeq: 1 INVITE
Contact: <sip:alice@192.168.1.100:50001;transport=tcp>
Content-Length: 0

`

	pkt := createTCPPacket("192.168.1.100", "192.168.1.101", 50001, 5060, srcSeq, dstSeq, "PA", []byte(invite))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}
	srcSeq += uint32(len(invite))
	ts = ts.Add(time.Millisecond)

	// 486 Busy Here
	busy := `SIP/2.0 486 Busy Here
Via: SIP/2.0/TCP 192.168.1.100:50001;branch=z9hG4bK123failed
To: Bob <sip:bob@192.168.1.101>;tag=busytag
From: Alice <sip:alice@192.168.1.100>;tag=failed123
Call-ID: tcp-failed-call-99999@192.168.1.100
CSeq: 1 INVITE
Content-Length: 0

`

	pkt = createTCPPacket("192.168.1.101", "192.168.1.100", 5060, 50001, dstSeq, srcSeq, "PA", []byte(busy))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}

	fmt.Println("✓ Generated tcp_sip_failed_call.pcap")
	return nil
}

func generatePAssertedIdentityCall() error {
	f, w, err := createPCAPWriter("testdata/pcaps/tcp_sip_passerted_identity.pcap")
	if err != nil {
		return err
	}
	defer f.Close()

	srcSeq, dstSeq, err := writeTCPHandshake(w, "192.168.1.100", "192.168.1.101", 50002, 5060, 30000)
	if err != nil {
		return err
	}

	ts := time.Now().Add(5 * time.Millisecond)

	// INVITE with P-Asserted-Identity
	invite := `INVITE sip:bob@192.168.1.101 SIP/2.0
Via: SIP/2.0/TCP 192.168.1.100:50002;branch=z9hG4bKpai123
Max-Forwards: 70
To: Bob <sip:bob@192.168.1.101>
From: Alice <sip:alice@192.168.1.100>;tag=pai789
Call-ID: tcp-pai-call-77777@192.168.1.100
CSeq: 1 INVITE
Contact: <sip:alice@192.168.1.100:50002;transport=tcp>
P-Asserted-Identity: <sip:+14155551234@provider.com>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alice 53655765 2353687637 IN IP4 192.168.1.100
s=Session SDP
c=IN IP4 192.168.1.100
t=0 0
m=audio 8000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
`

	pkt := createTCPPacket("192.168.1.100", "192.168.1.101", 50002, 5060, srcSeq, dstSeq, "PA", []byte(invite))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}

	fmt.Println("✓ Generated tcp_sip_passerted_identity.pcap")
	return nil
}

func generateMultistreamCall() error {
	f, w, err := createPCAPWriter("testdata/pcaps/tcp_sip_multistream.pcap")
	if err != nil {
		return err
	}
	defer f.Close()

	srcSeq, dstSeq, err := writeTCPHandshake(w, "192.168.1.100", "192.168.1.200", 50003, 5060, 40000)
	if err != nil {
		return err
	}

	ts := time.Now().Add(5 * time.Millisecond)

	// INVITE with multiple streams
	invite := `INVITE sip:conference@192.168.1.200 SIP/2.0
Via: SIP/2.0/TCP 192.168.1.100:50003;branch=z9hG4bKconf123
Max-Forwards: 70
To: Conference <sip:conference@192.168.1.200>
From: Alice <sip:alice@192.168.1.100>;tag=conf456
Call-ID: tcp-multistream-88888@192.168.1.100
CSeq: 1 INVITE
Contact: <sip:alice@192.168.1.100:50003;transport=tcp>
Content-Type: application/sdp
Content-Length: 260

v=0
o=alice 53655765 2353687637 IN IP4 192.168.1.100
s=Conference Call
c=IN IP4 192.168.1.100
t=0 0
m=audio 8000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
m=audio 8002 RTP/AVP 0
a=rtpmap:0 PCMU/8000
m=audio 8004 RTP/AVP 8
a=rtpmap:8 PCMA/8000
`

	pkt := createTCPPacket("192.168.1.100", "192.168.1.200", 50003, 5060, srcSeq, dstSeq, "PA", []byte(invite))
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}, pkt); err != nil {
		return err
	}

	fmt.Println("✓ Generated tcp_sip_multistream.pcap")
	return nil
}
