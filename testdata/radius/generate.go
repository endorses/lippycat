// Command radius-fixtures generates deterministic synthetic acceptance inputs.
// It is deliberately independent of the future production RADIUS decoder.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type attribute struct {
	Type     byte   `json:"type"`
	ValueHex string `json:"value_hex"`
}

type observation struct {
	Record          int         `json:"record"`
	Timestamp       string      `json:"timestamp"`
	Association     string      `json:"association"`
	Request         string      `json:"associated_request,omitempty"`
	Diagnostic      string      `json:"diagnostic,omitempty"`
	Name            string      `json:"name"`
	Scope           string      `json:"capture_scope"`
	Operator        string      `json:"operator"`
	NAS             string      `json:"nas"`
	IPVersion       int         `json:"ip_version"`
	SourceIP        string      `json:"source_ip"`
	DestinationIP   string      `json:"destination_ip"`
	SourcePort      uint16      `json:"source_port"`
	DestinationPort uint16      `json:"destination_port"`
	Code            byte        `json:"code"`
	Identifier      byte        `json:"identifier"`
	Outcome         string      `json:"outcome"`
	Attributes      []attribute `json:"attributes"`
	RawFile         string      `json:"raw_radius_file,omitempty"`
	NASLine         bool        `json:"matches_operator_a_nas_line"`
	CircuitLine     bool        `json:"matches_operator_a_circuit_line"`
}

type manifest struct {
	Version         int           `json:"version"`
	LinkType        int           `json:"link_type"`
	ConfiguredPorts []uint16      `json:"configured_ports"`
	Observations    []observation `json:"observations"`
}

func avp(t byte, value []byte) []byte    { return append([]byte{t, byte(len(value) + 2)}, value...) }
func strAVP(t byte, value string) []byte { return avp(t, []byte(value)) }
func vsa(subs ...[]byte) []byte {
	b := []byte{0, 0, 13, 233} // DSL Forum vendor 3561.
	for _, s := range subs {
		b = append(b, s...)
	}
	return avp(26, b)
}
func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

func frame(o observation, payload []byte, fragmented bool) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp, o.SourcePort)
	binary.BigEndian.PutUint16(udp[2:], o.DestinationPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)
	src, dst := net.ParseIP(o.SourceIP), net.ParseIP(o.DestinationIP)
	var ip, pseudo []byte
	ether := []byte{2, 0, 0, 0, 0, 0x10, 2, 0, 0, 0, 0, 0x20, 8, 0}
	if o.IPVersion == 4 {
		ip = make([]byte, 20)
		ip[0] = 0x45
		ip[8] = 64
		ip[9] = 17
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		if fragmented {
			ip[6] = 0x20
		}
		copy(ip[12:], src.To4())
		copy(ip[16:], dst.To4())
		binary.BigEndian.PutUint16(ip[10:], checksum(ip))
		pseudo = append(append([]byte{}, ip[12:20]...), 0, 17, byte(len(udp)>>8), byte(len(udp)))
	} else {
		ether[12], ether[13] = 0x86, 0xdd
		ip = make([]byte, 40)
		ip[0] = 0x60
		ip[6] = 17
		ip[7] = 64
		copy(ip[8:], src.To16())
		copy(ip[24:], dst.To16())
		binary.BigEndian.PutUint16(ip[4:], uint16(len(udp)))
		pseudo = append(append([]byte{}, ip[8:40]...), 0, 0, byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, 17)
		if fragmented {
			ip[6] = 44
			binary.BigEndian.PutUint16(ip[4:], uint16(8+len(udp)))
			ip = append(ip, 17, 0, 0, 0, 0, 0, 0, 1) // Atomic fragment, still rejected.
		}
	}
	c := checksum(append(pseudo, udp...))
	if c == 0 {
		c = 65535
	}
	binary.BigEndian.PutUint16(udp[6:], c)
	if fragmented && o.IPVersion == 4 {
		udp = udp[:24] // First 24 bytes of a 28-byte UDP datagram; final fragment absent.
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		ip[10], ip[11] = 0, 0
		binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	}
	return append(append(ether, ip...), udp...)
}

func artifacts() map[string][]byte {
	files := make(map[string][]byte)
	m := manifest{Version: 1, LinkType: 1, ConfiguredPorts: []uint16{1812, 1813, 19120}}
	var pcap bytes.Buffer
	for _, v := range []any{uint32(0xa1b2c3d4), uint16(2), uint16(4), int32(0), uint32(0), uint32(65535), uint32(1)} {
		must(binary.Write(&pcap, binary.LittleEndian, v))
	}
	add := func(name string, code byte, family int, port uint16, client int, scope string, attrs [][]byte, outcome string, padded bool) {
		o := observation{Name: name, Scope: scope, Operator: "operator-a", NAS: "nas-a", IPVersion: family, SourceIP: fmt.Sprintf("192.0.2.%d", client), DestinationIP: "198.51.100.10", SourcePort: 40000, DestinationPort: port, Code: code, Identifier: 7, Outcome: outcome, Attributes: []attribute{}}
		o.Record = len(m.Observations) + 1
		o.Timestamp = fmt.Sprintf("%d.123456", 1700000000+len(m.Observations))
		o.Association = "request"
		if outcome != "valid" {
			o.Association = "not_applicable"
		}
		if outcome == "truncated" {
			o.Outcome, o.Diagnostic = "malformed", "declared_length_exceeds_udp_payload"
		}
		if scope == "poi-b" {
			o.Operator, o.NAS = "operator-b", "nas-b"
		}
		if family == 6 {
			o.SourceIP = fmt.Sprintf("2001:db8:1::%d", client)
			o.DestinationIP = "2001:db8:2::10"
		}
		if code == 2 || code == 3 || code == 5 || code == 11 {
			o.SourceIP, o.DestinationIP = o.DestinationIP, o.SourceIP
			o.SourcePort, o.DestinationPort = o.DestinationPort, o.SourcePort
			o.Association = "unique"
			o.Request = m.Observations[len(m.Observations)-1].Name
		}
		raw := make([]byte, 20)
		raw[0], raw[1] = code, 7
		for i := 4; i < 20; i++ {
			raw[i] = byte(len(m.Observations) + i)
		}
		for _, a := range attrs {
			raw = append(raw, a...)
			if outcome == "valid" {
				o.Attributes = append(o.Attributes, attribute{a[0], hex.EncodeToString(a[2:])})
				if scope == "poi-a" && a[0] == 87 && string(a[2:]) == "line-a" {
					o.NASLine = true
				}
				if scope == "poi-a" && a[0] == 26 && bytes.Contains(a, strAVP(1, "circuit-a")) {
					o.CircuitLine = true
				}
			}
		}
		binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
		if outcome == "truncated" {
			raw = raw[:len(raw)-1]
		}
		if outcome == "valid" {
			o.RawFile = "raw/" + name + ".bin"
			files[o.RawFile] = append([]byte(nil), raw...)
		}
		payload := append([]byte(nil), raw...)
		if padded {
			payload = append(payload, 0xde, 0xad, 0xbe, 0xef)
		}
		packet := frame(o, payload, outcome == "fragmented")
		for _, v := range []uint32{1700000000 + uint32(len(m.Observations)), 123456, uint32(len(packet)), uint32(len(packet))} {
			must(binary.Write(&pcap, binary.LittleEndian, v))
		}
		_, err := pcap.Write(packet)
		must(err)
		m.Observations = append(m.Observations, o)
	}
	identity := [][]byte{strAVP(1, "alice@example.test"), strAVP(31, "02-00-00-00-00-01"), strAVP(87, "line-a"), vsa(strAVP(1, "circuit-a")), avp(4, []byte{192, 0, 2, 1}), strAVP(32, "nas-a")}
	add("access-request-v4", 1, 4, 1812, 1, "poi-a", identity, "valid", true)
	add("access-accept-v4", 2, 4, 1812, 1, "poi-a", nil, "valid", false)
	add("access-request-client2-v6", 1, 6, 1812, 2, "poi-a", identity, "valid", false)
	add("access-reject-v6", 3, 6, 1812, 2, "poi-a", nil, "valid", false)
	add("custom-request-v6", 1, 6, 19120, 3, "poi-a", identity, "valid", false)
	add("access-challenge-custom-v6", 11, 6, 19120, 3, "poi-a", [][]byte{strAVP(24, "challenge-state")}, "valid", false)
	add("accounting-request-v4", 4, 4, 1813, 4, "poi-a", [][]byte{strAVP(1, "alice@example.test"), avp(40, []byte{0, 0, 0, 1}), strAVP(44, "session-synthetic")}, "valid", false)
	add("accounting-response-v4", 5, 4, 1813, 4, "poi-a", nil, "valid", false)
	add("accounting-request-v6", 4, 6, 1813, 5, "poi-a", [][]byte{strAVP(1, "alice@example.test")}, "valid", false)
	add("accounting-response-v6", 5, 6, 1813, 5, "poi-a", nil, "valid", false)
	add("accept-request-v6", 1, 6, 1812, 10, "poi-a", identity, "valid", false)
	add("access-accept-v6", 2, 6, 1812, 10, "poi-a", nil, "valid", false)
	add("reject-request-v4", 1, 4, 1812, 11, "poi-a", identity, "valid", false)
	add("access-reject-v4", 3, 4, 1812, 11, "poi-a", nil, "valid", false)
	add("challenge-request-v4", 1, 4, 19120, 12, "poi-a", identity, "valid", false)
	add("access-challenge-v4", 11, 4, 19120, 12, "poi-a", nil, "valid", false)
	add("line-collision-other-scope", 1, 4, 1812, 1, "poi-b", identity, "valid", false)
	add("access-accept-other-scope", 2, 4, 1812, 1, "poi-b", nil, "valid", false)
	add("repeated-grouped-vsa", 1, 4, 1812, 6, "poi-a", [][]byte{strAVP(1, "other@example.test"), strAVP(1, "alice@example.test"), vsa(strAVP(2, "remote-a"), strAVP(1, "circuit-a")), avp(222, []byte{0, 255})}, "valid", false)
	add("repeated-split-vsa", 1, 4, 1812, 7, "poi-a", [][]byte{vsa(strAVP(2, "remote-a")), vsa(strAVP(1, "circuit-a"))}, "valid", false)
	add("binary-user-name", 1, 4, 1812, 8, "poi-a", [][]byte{avp(1, []byte{0xff, 0, 0x41})}, "valid", false)
	add("malformed-avp", 1, 4, 1812, 9, "poi-a", [][]byte{{1, 1}}, "malformed", false)
	add("malformed-vsa", 1, 4, 1812, 9, "poi-a", [][]byte{avp(26, []byte{0, 0, 13, 233, 1, 20, 65})}, "malformed", false)
	add("truncated-radius", 1, 4, 1812, 9, "poi-a", identity, "truncated", false)
	add("ipv4-first-fragment", 1, 4, 1812, 9, "poi-a", nil, "fragmented", false)
	add("ipv6-atomic-fragment", 1, 6, 1812, 9, "poi-a", nil, "fragmented", false)
	files["acceptance.pcap"] = pcap.Bytes()
	b, err := json.MarshalIndent(m, "", "  ")
	must(err)
	files["expected.json"] = append(b, '\n')
	return files
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	check := flag.Bool("check", false, "check committed fixtures without writing")
	out := flag.String("out", "testdata/radius", "fixture directory relative to working directory")
	flag.Parse()
	for name, b := range artifacts() {
		path := filepath.Join(*out, name)
		if *check {
			got, err := os.ReadFile(path)
			must(err)
			if !bytes.Equal(got, b) {
				panic("stale fixture: " + path)
			}
			continue
		}
		must(os.MkdirAll(filepath.Dir(path), 0755))
		must(os.WriteFile(path, b, 0644))
	}
}
