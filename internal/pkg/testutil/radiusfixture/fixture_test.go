package radiusfixture

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// This checker reads the generated wire files independently of the builder.
// It verifies fixture truth; it does not test production decoder behavior.
func TestAcceptanceWire(t *testing.T) {
	dir := Write(t)
	b, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(dir, "acceptance.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 24 || binary.LittleEndian.Uint32(b) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(b[20:]) != 1 {
		t.Fatal("invalid PCAP header")
	}
	r := bytes.NewReader(b[24:])
	codes, families, scopes := map[byte]bool{}, map[int]bool{}, map[string]bool{}
	for index, o := range m.Observations {
		t.Run(o.Name, func(t *testing.T) {
			var h [4]uint32
			if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
				t.Fatal(err)
			}
			if h[0] != 1700000000+uint32(index) || h[1] != 123456 || h[2] != h[3] {
				t.Fatal("PCAP record metadata")
			}
			if o.Record != index+1 || o.Timestamp != fmt.Sprintf("%d.%06d", h[0], h[1]) {
				t.Fatal("manifest timestamp/ordinal")
			}
			packet := make([]byte, h[2])
			if _, err := io.ReadFull(r, packet); err != nil {
				t.Fatal(err)
			}
			ip := packet[14:]
			version := int(ip[0] >> 4)
			if version != o.IPVersion {
				t.Fatal("IP version")
			}
			var src, dst net.IP
			var udp []byte
			fragmented := false
			if version == 4 {
				if binary.BigEndian.Uint16(packet[12:]) != 0x0800 || int(binary.BigEndian.Uint16(ip[2:])) != len(ip) || ip[9] != 17 || checksum(ip[:20]) != 0 {
					t.Fatal("IPv4 header")
				}
				src, dst = net.IP(ip[12:16]), net.IP(ip[16:20])
				udp = ip[int(ip[0]&15)*4:]
				fragmented = binary.BigEndian.Uint16(ip[6:])&0x3fff != 0
			} else {
				if binary.BigEndian.Uint16(packet[12:]) != 0x86dd || int(binary.BigEndian.Uint16(ip[4:])) != len(ip)-40 {
					t.Fatal("IPv6 header")
				}
				src, dst = net.IP(ip[8:24]), net.IP(ip[24:40])
				udp = ip[40:]
				if ip[6] == 44 {
					fragmented = true
					if udp[0] != 17 {
						t.Fatal("fragment next header")
					}
					udp = udp[8:]
				} else if ip[6] != 17 {
					t.Fatal("IPv6 next header")
				}
			}
			if src.String() != o.SourceIP || dst.String() != o.DestinationIP || binary.BigEndian.Uint16(udp) != o.SourcePort || binary.BigEndian.Uint16(udp[2:]) != o.DestinationPort || (!fragmented && int(binary.BigEndian.Uint16(udp[4:])) != len(udp)) {
				t.Fatal("UDP endpoints or length")
			}
			var pseudo []byte
			if version == 4 {
				pseudo = append(append([]byte{}, src...), dst...)
				pseudo = append(pseudo, 0, 17, byte(len(udp)>>8), byte(len(udp)))
			} else {
				pseudo = append(append([]byte{}, src...), dst...)
				pseudo = append(pseudo, 0, 0, byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, 17)
			}
			if !(fragmented && version == 4) && checksum(append(pseudo, udp...)) != 0 {
				t.Fatal("UDP checksum")
			}
			raw := udp[8:]
			outcome := "valid"
			var attrs []attribute
			if fragmented {
				outcome = "fragmented"
			} else if len(raw) < 20 || int(binary.BigEndian.Uint16(raw[2:])) > len(raw) {
				outcome = "malformed"
			} else {
				raw = raw[:binary.BigEndian.Uint16(raw[2:])]
				attrs = []attribute{}
				for remaining := raw[20:]; len(remaining) > 0; {
					if len(remaining) < 2 || int(remaining[1]) > len(remaining) || remaining[1] < 2 {
						outcome = "malformed"
						break
					}
					a := remaining[:remaining[1]]
					remaining = remaining[remaining[1]:]
					if a[0] == 26 {
						if len(a) < 8 {
							outcome = "malformed"
							break
						}
						for inner := a[6:]; len(inner) > 0; {
							if len(inner) < 2 || inner[1] < 2 || int(inner[1]) > len(inner) {
								outcome = "malformed"
								break
							}
							inner = inner[inner[1]:]
						}
					}
					attrs = append(attrs, attribute{a[0], hex.EncodeToString(a[2:])})
				}
			}
			if outcome != o.Outcome {
				t.Fatalf("outcome %s, want %s", outcome, o.Outcome)
			}
			if raw[0] != o.Code || raw[1] != o.Identifier {
				t.Fatal("RADIUS code/identifier")
			}
			if outcome == "valid" {
				if o.Code == 1 || o.Code == 4 {
					if o.Association != "request" || o.Request != "" {
						t.Fatal("request association")
					}
				} else {
					candidates := []observation{}
					for _, prior := range m.Observations[:index] {
						compatible := prior.Code == 1 && (o.Code == 2 || o.Code == 3 || o.Code == 11) || prior.Code == 4 && o.Code == 5
						if compatible && prior.Outcome == "valid" && prior.Scope == o.Scope && prior.Identifier == o.Identifier && prior.SourceIP == o.DestinationIP && prior.DestinationIP == o.SourceIP && prior.SourcePort == o.DestinationPort && prior.DestinationPort == o.SourcePort {
							candidates = append(candidates, prior)
						}
					}
					if len(candidates) != 1 || o.Association != "unique" || o.Request != candidates[0].Name {
						t.Fatal("response association")
					}
				}
				codes[o.Code], families[version], scopes[o.Scope] = true, true, true
				golden, err := os.ReadFile(filepath.Join(dir, o.RawFile))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(raw, golden) {
					t.Fatal("raw RADIUS golden mismatch")
				}
				if !reflect.DeepEqual(attrs, o.Attributes) {
					t.Fatal("attribute observations differ")
				}
				nasLine, circuitLine := false, false
				for _, a := range attrs {
					value, err := hex.DecodeString(a.ValueHex)
					if err != nil {
						t.Fatal(err)
					}
					if a.Type == 87 && string(value) == "line-a" {
						nasLine = true
					}
					if a.Type == 26 && binary.BigEndian.Uint32(value) == 3561 {
						for inner := value[4:]; len(inner) > 0; inner = inner[inner[1]:] {
							if inner[0] == 1 && string(inner[2:inner[1]]) == "circuit-a" {
								circuitLine = true
							}
						}
					}
				}
				inScope := o.Scope == "poi-a" && o.Operator == "operator-a" && o.NAS == "nas-a"
				if o.NASLine != (inScope && nasLine) || o.CircuitLine != (inScope && circuitLine) {
					t.Fatal("known-line mapping")
				}
			} else if o.RawFile != "" || o.NASLine || o.CircuitLine || len(o.Attributes) != 0 {
				t.Fatal("invalid observation exposes attribution")
			}
		})
	}
	if r.Len() != 0 {
		t.Fatal("unlisted packets")
	}
	for _, code := range []byte{1, 2, 3, 4, 5, 11} {
		if !codes[code] {
			t.Errorf("missing code %d", code)
		}
		for _, family := range []int{4, 6} {
			found := false
			for _, o := range m.Observations {
				if o.Outcome == "valid" && o.Code == code && o.IPVersion == family {
					found = true
				}
			}
			if !found {
				t.Errorf("missing code %d IPv%d", code, family)
			}
		}
	}
	if len(families) != 2 || len(scopes) != 2 {
		t.Fatal("missing family/scope coverage")
	}
}

func TestExpectedManifest(t *testing.T) {
	if !bytes.Equal(artifacts()["expected.json"], expected) {
		t.Fatal("generated observations differ from the independent expected manifest")
	}
}
