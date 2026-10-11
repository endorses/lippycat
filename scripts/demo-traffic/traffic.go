package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildCycle constructs synthetic observations, without opening sockets or using
// live credentials. TCP transports finish cleanly; TLS and SSH stop after their
// greetings, and WireGuard is only a recognizable, invalid cryptographic sample.
func buildCycle(cycle int) ([][]byte, error) {
	if cycle < 0 {
		return nil, fmt.Errorf("cycle must be non-negative: %d", cycle)
	}
	port := uint16(40000 + (cycle%1000)*16)
	mediaPort := uint16(16400 + (cycle%1000)*2)
	host := fmt.Sprintf("demo-%d.example.test", cycle)
	var flows [][][]byte
	add := func(name string, packets [][]byte, err error) error {
		if err != nil {
			return fmt.Errorf("build %s cycle %d: %w", name, cycle, err)
		}
		flows = append(flows, packets)
		return nil
	}
	packets, err := demoDNS(cycle, port, host)
	if err := add("DNS", packets, err); err != nil {
		return nil, err
	}
	packets, err = demoCall(cycle, mediaPort)
	if err := add("SIP/RTP", packets, err); err != nil {
		return nil, err
	}
	body := fmt.Sprintf("Synthetic traffic demo, cycle %d.\n", cycle)
	tcpFlows := []struct {
		name     string
		server   string
		port     uint16
		messages []demoMessage
	}{
		{"HTTP", "198.51.100.80", 80, []demoMessage{
			{false, []byte(fmt.Sprintf("GET /demo/%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: lippycat-synthetic-demo\r\nConnection: close\r\n\r\n", cycle, host))},
			{true, []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body))},
		}},
		{"TLS", "198.51.100.20", 443, []demoMessage{
			{false, demoTLSHello(cycle, host, false)},
			{true, demoTLSHello(cycle, host, true)},
		}},
		{"SSH", "198.51.100.22", 22, []demoMessage{
			{true, []byte("SSH-2.0-LippycatSyntheticServer_1.0\r\n")},
			{false, []byte("SSH-2.0-LippycatSyntheticClient_1.0\r\n")},
		}},
		{"TCP", "198.51.100.90", 49090, []demoMessage{
			{false, []byte("synthetic plain TCP request\r\n")},
			{true, []byte("synthetic plain TCP response\r\n")},
		}},
		{"SMTP", "198.51.100.25", 25, []demoMessage{
			{true, []byte("220 mail.example.test ESMTP synthetic demo\r\n")},
			{false, []byte("EHLO sender.example.test\r\n")},
			{true, []byte("250 mail.example.test Hello synthetic sender\r\n")},
			{false, []byte("MAIL FROM:<avery@example.test>\r\n")},
			{true, []byte("250 2.1.0 Sender accepted\r\n")},
			{false, []byte("RCPT TO:<morgan@example.test>\r\n")},
			{true, []byte("250 2.1.5 Recipient accepted\r\n")},
			{false, []byte("DATA\r\n")},
			{true, []byte("354 End synthetic message with <CRLF>.<CRLF>\r\n")},
			{false, []byte(fmt.Sprintf("From: Avery <avery@example.test>\r\nTo: Morgan <morgan@example.test>\r\nSubject: Synthetic demo %d\r\nMessage-ID: <demo-%d@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nThis is fictional demonstration traffic.\r\n.\r\n", cycle, cycle))},
			{true, []byte("250 2.0.0 Synthetic message accepted\r\n")},
			{false, []byte("QUIT\r\n")},
			{true, []byte("221 2.0.0 Goodbye\r\n")},
		}},
		{"IMAP", "198.51.100.143", 143, []demoMessage{
			{true, []byte("* OK mail.example.test IMAP4rev1 synthetic server ready\r\n")},
			{false, []byte("a001 CAPABILITY\r\n")},
			{true, []byte("* CAPABILITY IMAP4rev1 LOGINDISABLED\r\na001 OK CAPABILITY completed\r\n")},
			{false, []byte("a002 NOOP\r\n")},
			{true, []byte("a002 OK NOOP completed\r\n")},
			{false, []byte("a003 LOGOUT\r\n")},
			{true, []byte("* BYE Synthetic server logging out\r\na003 OK LOGOUT completed\r\n")},
		}},
		{"POP3", "198.51.100.110", 110, []demoMessage{
			{true, []byte("+OK mail.example.test POP3 synthetic server ready\r\n")},
			{false, []byte("CAPA\r\n")},
			{true, []byte("+OK Capability list follows\r\nUSER\r\n.\r\n")},
			{false, []byte("QUIT\r\n")},
			{true, []byte("+OK Synthetic server signing off\r\n")},
		}},
	}
	for i, flow := range tcpFlows {
		packets, err = demoTCP(cycle, flow.server, port+uint16(i)+1, flow.port, flow.messages)
		if err := add(flow.name, packets, err); err != nil {
			return nil, err
		}
	}
	for _, flow := range []struct {
		name string
		make func() ([][]byte, error)
	}{
		{"ARP", demoARP},
		{"ICMP", func() ([][]byte, error) { return demoEcho(cycle, false) }},
		{"ICMPv6", func() ([][]byte, error) { return demoEcho(cycle, true) }},
		{"WireGuard", func() ([][]byte, error) { return demoWireGuard(cycle, port+8) }},
		{"UDP", func() ([][]byte, error) {
			return demoDatagrams(cycle, "192.0.2.10", "198.51.100.91", port+9, 49091, []demoMessage{
				{false, []byte("synthetic plain UDP request")},
				{true, []byte("synthetic plain UDP response")},
			})
		}},
		{"DHCP", func() ([][]byte, error) { return demoDHCP(cycle) }},
		{"NTP", func() ([][]byte, error) { return demoNTP(cycle, port+10) }},
		{"RADIUS", func() ([][]byte, error) { return demoRADIUS(cycle, port+11) }},
	} {
		packets, err = flow.make()
		if err := add(flow.name, packets, err); err != nil {
			return nil, err
		}
	}
	// Interleave independent exchanges, preserving order within each exchange.
	var result [][]byte
	for index := 0; ; index++ {
		added := false
		for _, flow := range flows {
			if index < len(flow) {
				result = append(result, flow[index])
				added = true
			}
		}
		if !added {
			return result, nil
		}
	}
}

type demoMessage struct {
	fromServer bool
	payload    []byte
}

func demoEthernet(reverse bool, typ layers.EthernetType) *layers.Ethernet {
	client := net.HardwareAddr{2, 0, 0, 0, 0, 0x10}
	server := net.HardwareAddr{2, 0, 0, 0, 0, 0x20}
	if reverse {
		client, server = server, client
	}
	return &layers.Ethernet{SrcMAC: client, DstMAC: server, EthernetType: typ}
}

func demoIPv4(cycle int, src, dst string, protocol layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{
		Version: 4, TTL: 64, Id: uint16(cycle), Flags: layers.IPv4DontFragment,
		Protocol: protocol, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4(),
	}
}

func demoSerialize(stack ...gopacket.SerializableLayer) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stack...); err != nil {
		return nil, fmt.Errorf("serialize Ethernet frame: %w", err)
	}
	return append([]byte(nil), buffer.Bytes()...), nil
}

func demoUDP(cycle int, src, dst string, sport, dport uint16, reverse bool, payload gopacket.SerializableLayer) ([]byte, error) {
	ip := demoIPv4(cycle, src, dst, layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("set UDP checksum network layer: %w", err)
	}
	ethernet := demoEthernet(reverse, layers.EthernetTypeIPv4)
	if dst == "255.255.255.255" {
		ethernet.DstMAC = net.HardwareAddr{255, 255, 255, 255, 255, 255}
	}
	return demoSerialize(ethernet, ip, udp, payload)
}

func demoDatagrams(cycle int, client, server string, cport, sport uint16, messages []demoMessage) ([][]byte, error) {
	var frames [][]byte
	for i, message := range messages {
		src, dst, sp, dp := client, server, cport, sport
		if message.fromServer {
			src, dst, sp, dp = server, client, sport, cport
		}
		frame, err := demoUDP(cycle, src, dst, sp, dp, message.fromServer, gopacket.Payload(message.payload))
		if err != nil {
			return nil, fmt.Errorf("datagram %d: %w", i, err)
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func demoDNS(cycle int, port uint16, host string) ([][]byte, error) {
	question := layers.DNSQuestion{Name: []byte(host), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	query := &layers.DNS{ID: uint16(cycle), RD: true, Questions: []layers.DNSQuestion{question}}
	answer := &layers.DNS{ID: uint16(cycle), QR: true, RD: true, RA: true,
		Questions: []layers.DNSQuestion{question},
		Answers:   []layers.DNSResourceRecord{{Name: []byte(host), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.IPv4(198, 51, 100, 80)}},
	}
	q, err := demoUDP(cycle, "192.0.2.10", "198.51.100.53", port, 53, false, query)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	a, err := demoUDP(cycle, "198.51.100.53", "192.0.2.10", 53, port, true, answer)
	if err != nil {
		return nil, fmt.Errorf("answer: %w", err)
	}
	return [][]byte{q, a}, nil
}

func demoTCP(cycle int, server string, cport, sport uint16, messages []demoMessage) ([][]byte, error) {
	seq := [2]uint32{100000 + uint32(cycle)*10000, 200000 + uint32(cycle)*10000}
	var frames [][]byte
	packet := func(reverse, syn, ack, fin bool, payload []byte) error {
		direction, other := 0, 1
		src, dst, sp, dp := "192.0.2.10", server, cport, sport
		if reverse {
			direction, other = 1, 0
			src, dst, sp, dp = server, "192.0.2.10", sport, cport
		}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp),
			Seq: seq[direction], SYN: syn, ACK: ack, FIN: fin, PSH: len(payload) != 0, Window: 32768}
		if ack {
			tcp.Ack = seq[other]
		}
		if syn {
			tcp.Options = []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionData: []byte{5, 180}}}
		}
		ip := demoIPv4(cycle, src, dst, layers.IPProtocolTCP)
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			return fmt.Errorf("set TCP checksum network layer: %w", err)
		}
		frame, err := demoSerialize(demoEthernet(reverse, layers.EthernetTypeIPv4), ip, tcp, gopacket.Payload(payload))
		if err != nil {
			return err
		}
		frames = append(frames, frame)
		seq[direction] += uint32(len(payload))
		if syn || fin {
			seq[direction]++
		}
		return nil
	}
	for i, handshake := range []struct{ reverse, syn, ack bool }{{false, true, false}, {true, true, true}, {false, false, true}} {
		if err := packet(handshake.reverse, handshake.syn, handshake.ack, false, nil); err != nil {
			return nil, fmt.Errorf("TCP handshake packet %d: %w", i, err)
		}
	}
	for i, message := range messages {
		if err := packet(message.fromServer, false, true, false, message.payload); err != nil {
			return nil, fmt.Errorf("TCP message %d: %w", i, err)
		}
		if err := packet(!message.fromServer, false, true, false, nil); err != nil {
			return nil, fmt.Errorf("TCP message %d acknowledgment: %w", i, err)
		}
	}
	for i, close := range []struct{ reverse, fin bool }{{false, true}, {true, false}, {true, true}, {false, false}} {
		if err := packet(close.reverse, false, true, close.fin, nil); err != nil {
			return nil, fmt.Errorf("TCP close packet %d: %w", i, err)
		}
	}
	return frames, nil
}

func demoTLSHello(cycle int, host string, server bool) []byte {
	identity := fmt.Sprintf("synthetic TLS client random %d", cycle)
	if server {
		identity = fmt.Sprintf("synthetic TLS server random %d", cycle)
	}
	random := sha256.Sum256([]byte(identity))
	body := append([]byte{3, 3}, random[:]...)
	body = append(body, 0) // Empty session ID.
	kind := byte(1)
	if server {
		kind = 2
		body = append(body, 0xc0, 0x2f, 0) // TLS 1.2 cipher, null compression.
		body = append(body, 0, 0)          // No extensions.
	} else {
		body = append(body, 0, 4, 0xc0, 0x2f, 0, 0x2f, 1, 0)
		name := binary.BigEndian.AppendUint16([]byte{0}, uint16(len(host)))
		name = append(name, host...)
		sni := binary.BigEndian.AppendUint16(nil, uint16(len(name)))
		sni = append(sni, name...)
		extensions := binary.BigEndian.AppendUint16([]byte{0, 0}, uint16(len(sni)))
		extensions = append(extensions, sni...)
		// Supported groups (secp256r1), uncompressed EC points, ALPN HTTP/1.1.
		extensions = append(extensions, 0, 10, 0, 4, 0, 2, 0, 23, 0, 11, 0, 2, 1, 0)
		extensions = append(extensions, 0, 16, 0, 11, 0, 9, 8)
		extensions = append(extensions, "http/1.1"...)
		body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
		body = append(body, extensions...)
	}
	handshake := append([]byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := binary.BigEndian.AppendUint16([]byte{22, 3, 3}, uint16(len(handshake)))
	return append(record, handshake...)
}

func demoCall(cycle int, mediaPort uint16) ([][]byte, error) {
	callID := fmt.Sprintf("synthetic-call-%d@example.test", cycle)
	branch := fmt.Sprintf("z9hG4bK-demo-%d", cycle)
	sdp := func(server bool) string {
		address, port := "192.0.2.10", mediaPort
		if server {
			address, port = "198.51.100.50", mediaPort+2000
		}
		return fmt.Sprintf("v=0\r\no=demo %d 1 IN IP4 %s\r\ns=Synthetic demonstration\r\nc=IN IP4 %s\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n", cycle+1, address, address, port)
	}
	sip := func(start, method string, number int, tagged, server bool, body string) []byte {
		to := "<sip:morgan@example.test>"
		if tagged {
			to += ";tag=demo-morgan"
		}
		contentType := ""
		if body != "" {
			contentType = "Content-Type: application/sdp\r\n"
		}
		contact := "avery@192.0.2.10"
		if server {
			contact = "morgan@198.51.100.50"
		}
		transactionBranch := branch
		if method != "INVITE" {
			transactionBranch += "-" + method
		}
		return []byte(fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=%s\r\nMax-Forwards: 70\r\nFrom: Avery <sip:avery@example.test>;tag=demo-avery\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %d %s\r\nContact: <sip:%s:5060>\r\nUser-Agent: lippycat-synthetic-demo\r\n%sContent-Length: %d\r\n\r\n%s", start, transactionBranch, to, callID, number, method, contact, contentType, len(body), body))
	}
	messages := []demoMessage{
		{false, sip("INVITE sip:morgan@example.test SIP/2.0", "INVITE", 1, false, false, sdp(false))},
		{true, sip("SIP/2.0 180 Ringing", "INVITE", 1, true, true, "")},
		{true, sip("SIP/2.0 200 OK", "INVITE", 1, true, true, sdp(true))},
		{false, sip("ACK sip:morgan@198.51.100.50:5060 SIP/2.0", "ACK", 1, true, false, "")},
	}
	frames, err := demoDatagrams(cycle, "192.0.2.10", "198.51.100.50", 5060, 5060, messages)
	if err != nil {
		return nil, fmt.Errorf("SIP establishment: %w", err)
	}
	for i := 0; i < 8; i++ {
		payload := make([]byte, 172)
		payload[0] = 0x80 // RTPv2, PCMU, no extensions.
		binary.BigEndian.PutUint16(payload[2:4], uint16(100+i/2))
		binary.BigEndian.PutUint32(payload[4:8], uint32(8000+(i/2)*160))
		ssrc := uint32(0x10203040)
		if i%2 != 0 {
			ssrc = 0x50607080
		}
		binary.BigEndian.PutUint32(payload[8:12], ssrc)
		copy(payload[12:], bytes.Repeat([]byte{0xff}, 160)) // 20 ms of PCMU silence.
		media, err := demoDatagrams(cycle, "192.0.2.10", "198.51.100.50", mediaPort, mediaPort+2000, []demoMessage{{i%2 != 0, payload}})
		if err != nil {
			return nil, fmt.Errorf("RTP packet %d: %w", i, err)
		}
		frames = append(frames, media...)
	}
	end, err := demoDatagrams(cycle, "192.0.2.10", "198.51.100.50", 5060, 5060, []demoMessage{
		{false, sip("BYE sip:morgan@198.51.100.50:5060 SIP/2.0", "BYE", 2, true, false, "")},
		{true, sip("SIP/2.0 200 OK", "BYE", 2, true, true, "")},
	})
	if err != nil {
		return nil, fmt.Errorf("SIP termination: %w", err)
	}
	return append(frames, end...), nil
}

func demoARP() ([][]byte, error) {
	client := demoEthernet(false, layers.EthernetTypeARP).SrcMAC
	server := demoEthernet(true, layers.EthernetTypeARP).SrcMAC
	var frames [][]byte
	for _, reply := range []bool{false, true} {
		eth := demoEthernet(reply, layers.EthernetTypeARP)
		arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, Operation: layers.ARPRequest,
			SourceHwAddress: client, SourceProtAddress: net.IPv4(192, 0, 2, 10).To4(),
			DstHwAddress: make([]byte, 6), DstProtAddress: net.IPv4(192, 0, 2, 1).To4()}
		if reply {
			arp.Operation = layers.ARPReply
			arp.SourceHwAddress, arp.DstHwAddress = server, client
			arp.SourceProtAddress, arp.DstProtAddress = arp.DstProtAddress, arp.SourceProtAddress
		} else {
			eth.DstMAC = net.HardwareAddr{255, 255, 255, 255, 255, 255}
		}
		frame, err := demoSerialize(eth, arp)
		if err != nil {
			return nil, fmt.Errorf("ARP reply=%t: %w", reply, err)
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func demoEcho(cycle int, ipv6 bool) ([][]byte, error) {
	var frames [][]byte
	for _, reply := range []bool{false, true} {
		payload := gopacket.Payload([]byte(fmt.Sprintf("synthetic echo cycle %d", cycle)))
		var frame []byte
		var err error
		if ipv6 {
			src, dst := net.ParseIP("2001:db8:1::10"), net.ParseIP("2001:db8:2::1")
			typ := uint8(layers.ICMPv6TypeEchoRequest)
			if reply {
				src, dst, typ = dst, src, layers.ICMPv6TypeEchoReply
			}
			ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6, SrcIP: src, DstIP: dst}
			icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(typ, 0)}
			if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
				return nil, fmt.Errorf("set ICMPv6 checksum network layer: %w", err)
			}
			frame, err = demoSerialize(demoEthernet(reply, layers.EthernetTypeIPv6), ip, icmp,
				&layers.ICMPv6Echo{Identifier: uint16(cycle), SeqNumber: 1}, payload)
		} else {
			src, dst := "192.0.2.10", "198.51.100.1"
			typ := uint8(layers.ICMPv4TypeEchoRequest)
			if reply {
				src, dst, typ = dst, src, layers.ICMPv4TypeEchoReply
			}
			icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typ, 0), Id: uint16(cycle), Seq: 1}
			frame, err = demoSerialize(demoEthernet(reply, layers.EthernetTypeIPv4), demoIPv4(cycle, src, dst, layers.IPProtocolICMPv4), icmp, payload)
		}
		if err != nil {
			return nil, fmt.Errorf("echo reply=%t: %w", reply, err)
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func demoWireGuard(cycle int, port uint16) ([][]byte, error) {
	// Correct initiation envelope, deliberately invalid key/ciphertext/MAC fields.
	// The explicit marker makes it clear this is not a usable VPN handshake.
	payload := make([]byte, 148)
	payload[0] = 1
	binary.LittleEndian.PutUint32(payload[4:8], uint32(cycle)+1)
	marker := []byte("SYNTHETIC-DEMO-NOT-VALID-KEY-MATERIAL")
	for i := 8; i < len(payload); i++ {
		payload[i] = marker[(i-8)%len(marker)]
	}
	return demoDatagrams(cycle, "192.0.2.10", "198.51.100.60", port, 51820, []demoMessage{{false, payload}})
}

func demoDHCP(cycle int) ([][]byte, error) {
	discover := make([]byte, 240)
	discover[0], discover[1], discover[2] = 1, 1, 6
	binary.BigEndian.PutUint32(discover[4:8], 0x12340000+uint32(cycle))
	discover[10] = 0x80 // Broadcast flag.
	copy(discover[28:34], demoEthernet(false, layers.EthernetTypeIPv4).SrcMAC)
	copy(discover[236:240], []byte{99, 130, 83, 99})
	host := []byte("synthetic-demo")
	discover = append(discover, 53, 1, 1, 61, 7, 1, 2, 0, 0, 0, 0, 0x10, 12, byte(len(host)))
	discover = append(discover, host...)
	discover = append(discover, 55, 3, 1, 3, 6, 255)
	offer := append([]byte(nil), discover[:240]...)
	offer[0] = 2
	copy(offer[16:20], net.IPv4(192, 0, 2, 10).To4())
	copy(offer[20:24], net.IPv4(192, 0, 2, 1).To4())
	offer = append(offer, 53, 1, 2, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0x0e, 0x10,
		1, 4, 255, 255, 255, 0, 3, 4, 192, 0, 2, 1, 6, 4, 198, 51, 100, 53, 255)
	request, err := demoUDP(cycle, "0.0.0.0", "255.255.255.255", 68, 67, false, gopacket.Payload(discover))
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	response, err := demoUDP(cycle, "192.0.2.1", "255.255.255.255", 67, 68, true, gopacket.Payload(offer))
	if err != nil {
		return nil, fmt.Errorf("offer: %w", err)
	}
	return [][]byte{request, response}, nil
}

func demoNTP(cycle int, port uint16) ([][]byte, error) {
	request := make([]byte, 48)
	request[0], request[2], request[3] = 0x23, 6, 236 // NTPv4 client, poll 64s, precision -20.
	transmit := uint64(0xee43fc0080000000) + uint64(cycle)*0x100000000
	binary.BigEndian.PutUint64(request[40:48], transmit)
	response := append([]byte(nil), request...)
	response[0], response[1] = 0x24, 2 // NTPv4 server, stratum 2.
	copy(response[12:16], net.IPv4(192, 0, 2, 123).To4())
	binary.BigEndian.PutUint64(response[16:24], transmit-0x100000000)
	copy(response[24:32], request[40:48])
	binary.BigEndian.PutUint64(response[32:40], transmit+0x01000000)
	binary.BigEndian.PutUint64(response[40:48], transmit+0x02000000)
	return demoDatagrams(cycle, "192.0.2.10", "198.51.100.123", port, 123, []demoMessage{{false, request}, {true, response}})
}

func demoRADIUS(cycle int, port uint16) ([][]byte, error) {
	packet := func(code byte, attributes ...[]byte) []byte {
		payload := make([]byte, 20)
		payload[0], payload[1] = code, byte(cycle)
		// Opaque fixture authenticator; no secret and no authentication claim.
		copy(payload[4:20], "SYNTHETIC-DEMO!!")
		for _, attribute := range attributes {
			payload = append(payload, attribute...)
		}
		binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)))
		return payload
	}
	attribute := func(kind byte, value string) []byte {
		return append([]byte{kind, byte(len(value) + 2)}, value...)
	}
	request := packet(1, attribute(1, "avery@example.test"), []byte{4, 6, 192, 0, 2, 10}, attribute(32, "synthetic-nas"))
	accept := packet(2, attribute(18, "Synthetic acceptance; authenticator is a placeholder"))
	return demoDatagrams(cycle, "192.0.2.10", "198.51.100.181", port, 1812, []demoMessage{{false, request}, {true, accept}})
}
