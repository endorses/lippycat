package radius

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestAcceptancePackets(t *testing.T) {
	root := "../../../testdata/radius"
	manifest, err := os.ReadFile(filepath.Join(root, "expected.json"))
	require.NoError(t, err)
	var expected struct {
		Observations []struct {
			Name, Outcome   string
			IPVersion       uint8  `json:"ip_version"`
			SourceIP        string `json:"source_ip"`
			DestinationIP   string `json:"destination_ip"`
			SourcePort      uint16 `json:"source_port"`
			DestinationPort uint16 `json:"destination_port"`
			RawFile         string `json:"raw_radius_file"`
			Attributes      []struct {
				Type  uint8
				Value string `json:"value_hex"`
			}
		}
	}
	require.NoError(t, json.Unmarshal(manifest, &expected))
	f, err := os.Open(filepath.Join(root, "acceptance.pcap"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	for _, want := range expected.Observations {
		b, ci, err := r.ReadPacketData()
		require.NoError(t, err)
		t.Run(want.Name, func(t *testing.T) {
			o, outcome, err := DecodePacket(b, r.LinkType(), ci, CaptureScope{}, Identity{}, 19120)
			require.Equal(t, want.Outcome, string(outcome))
			require.Equal(t, b, o.Packet)
			if outcome != OutcomeValid {
				require.Error(t, err)
				require.Nil(t, o.Message)
				require.Empty(t, o.NAS)
				require.Empty(t, o.Direct)
				require.Empty(t, o.Inherited)
				return
			}
			require.NoError(t, err)
			gold, err := os.ReadFile(filepath.Join(root, want.RawFile))
			require.NoError(t, err)
			require.Equal(t, gold, o.Message.Raw)
			require.Equal(t, want.IPVersion, o.Endpoints.IPFamily)
			require.Equal(t, want.SourceIP, o.Endpoints.Source.Addr().String())
			require.Equal(t, want.DestinationIP, o.Endpoints.Destination.Addr().String())
			require.Equal(t, want.SourcePort, o.Endpoints.Source.Port())
			require.Equal(t, want.DestinationPort, o.Endpoints.Destination.Port())
			require.Len(t, o.Message.Attributes, len(want.Attributes))
			for i, a := range want.Attributes {
				require.Equal(t, a.Type, o.Message.Attributes[i].Type)
				require.Equal(t, a.Value, hex.EncodeToString(o.Message.Attributes[i].Value))
			}
			if o.Message.Code == 1 || o.Message.Code == 4 {
				require.Equal(t, o.Endpoints.Source, o.Endpoints.Client)
			} else {
				require.Equal(t, o.Endpoints.Destination, o.Endpoints.Client)
			}
			copyBefore := o.Clone()
			clear(b)
			require.Equal(t, copyBefore, o)
		})
	}
	_, _, err = r.ReadPacketData()
	require.ErrorIs(t, err, io.EOF)
}

func testIPPacket(v6 bool, port uint16) []byte {
	h := 20
	if v6 {
		h = 40
	}
	b := make([]byte, h+8+20)
	if v6 {
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:6], 28)
		b[6] = 17
		b[23] = 1
		b[39] = 2
	} else {
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		b[9] = 17
		b[12] = 192
		b[16] = 198
	}
	binary.BigEndian.PutUint16(b[h:h+2], 40000)
	binary.BigEndian.PutUint16(b[h+2:h+4], port)
	binary.BigEndian.PutUint16(b[h+4:h+6], 28)
	b[h+8] = 1
	binary.BigEndian.PutUint16(b[h+10:h+12], 20)
	return b
}

func TestPacketValidation(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		b := testIPPacket(v6, 1813)
		ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(b), Length: len(b)}
		_, out, err := DecodePacket(b, layers.LinkTypeRaw, ci, CaptureScope{}, Identity{})
		require.NoError(t, err)
		require.Equal(t, OutcomeValid, out)
		for i := 0; i < len(b); i++ {
			_, out, err := DecodePacket(b[:i], layers.LinkTypeRaw, ci, CaptureScope{}, Identity{})
			require.Error(t, err)
			require.NotEqual(t, OutcomeValid, out)
		}
		custom := testIPPacket(v6, 19120)
		_, out, err = DecodePacket(custom, layers.LinkTypeRaw, ci, CaptureScope{}, Identity{})
		require.Error(t, err)
		require.Equal(t, OutcomeUnsupported, out)
		_, out, err = DecodePacket(custom, layers.LinkTypeRaw, ci, CaptureScope{}, Identity{}, 19120)
		require.NoError(t, err)
		require.Equal(t, OutcomeValid, out)
		ci.Length++
		_, out, err = DecodePacket(b, layers.LinkTypeRaw, ci, CaptureScope{}, Identity{})
		require.Error(t, err)
		require.Equal(t, OutcomeMalformed, out)
	}
}

func TestIPv6ExtensionsAndFragments(t *testing.T) {
	for _, ext := range []byte{0, 43, 60, 51} {
		b := testIPPacket(true, 1812)
		extSize := 8
		if ext == 51 {
			extSize = 16
		}
		b = append(b[:40], append(make([]byte, extSize), b[40:]...)...)
		b[6] = ext
		b[40] = 17
		if ext == 51 {
			b[41] = 2
		}
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
		ci := gopacket.CaptureInfo{CaptureLength: len(b), Length: len(b)}
		_, out, err := DecodePacket(b, layers.LinkTypeRaw, ci, CaptureScope{}, Identity{})
		require.NoError(t, err)
		require.Equal(t, OutcomeValid, out)
		b[40] = 44
		_, out, err = DecodePacket(b, layers.LinkTypeRaw, ci, CaptureScope{}, Identity{})
		require.ErrorIs(t, err, ErrFragmented)
		require.Equal(t, OutcomeFragmented, out)
	}
	for _, flags := range []uint16{0x2000, 1, 0x2001} {
		b := testIPPacket(false, 1812)
		binary.BigEndian.PutUint16(b[6:8], flags)
		_, out, err := DecodePacket(b[:20], layers.LinkTypeRaw, gopacket.CaptureInfo{}, CaptureScope{}, Identity{})
		require.ErrorIs(t, err, ErrFragmented)
		require.Equal(t, OutcomeFragmented, out)
	}
}

func FuzzDecodePacket(f *testing.F) {
	f.Add(testIPPacket(false, 1812), false)
	f.Add(testIPPacket(true, 1813), true)
	f.Fuzz(func(t *testing.T, b []byte, ethernet bool) {
		link := layers.LinkTypeRaw
		if ethernet {
			link = layers.LinkTypeEthernet
		}
		o, out, err := DecodePacket(b, link, gopacket.CaptureInfo{CaptureLength: len(b), Length: len(b)}, CaptureScope{}, Identity{})
		if !bytes.Equal(b, o.Packet) {
			t.Fatal("packet bytes changed")
		}
		if out == OutcomeValid {
			if err != nil || o.Message == nil {
				t.Fatal("invalid success")
			}
		} else if err == nil || o.Message != nil || len(o.Direct) != 0 || len(o.Inherited) != 0 {
			t.Fatal("rejection exposed attribution")
		}
	})
}
