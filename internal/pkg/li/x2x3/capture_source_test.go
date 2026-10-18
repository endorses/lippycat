package x2x3

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func sourceProduct(t *testing.T, node, intf string, domain uint32, known bool) *PDU {
	t.Helper()
	source, err := types.NewCaptureSource(node, intf, domain, known)
	require.NoError(t, err)
	attr, err := EncodeCaptureSource(source)
	require.NoError(t, err)
	product := NewX3RTPPDU(uuid.New(), 1)
	product.AddAttribute(attr)
	return product
}

func TestCaptureSourceCodec(t *testing.T) {
	for _, known := range []bool{false, true} {
		product := sourceProduct(t, "hunter-ä", "eth0", 0, known)
		data, err := product.MarshalBinary()
		require.NoError(t, err)
		source, available, err := DecodeProductCaptureSource(data)
		require.NoError(t, err)
		require.True(t, available)
		require.Equal(t, "hunter-ä", source.NodeID())
		require.Equal(t, "eth0", source.Interface())
		domain, domainKnown := source.ObservationDomain()
		require.Zero(t, domain)
		require.Equal(t, known, domainKnown)
	}
	maximum := sourceProduct(t, strings.Repeat("a", 4096), strings.Repeat("b", 4096), ^uint32(0), true)
	wire, err := maximum.MarshalBinary()
	require.NoError(t, err)
	_, available, err := DecodeProductCaptureSource(wire)
	require.NoError(t, err)
	require.True(t, available)
	legacy := NewX2SIPPDU(uuid.New(), 1)
	legacy.AddAttribute(TLVAttribute{Type: AttrProprietary, Value: []byte("other.vendor.extension")})
	_, available, err = DecodeCaptureSource(legacy)
	require.NoError(t, err)
	require.False(t, available)
	_, err = EncodeCaptureSource(types.CaptureSource{})
	require.Error(t, err)
}

func TestCaptureSourceRejectsMalformedValues(t *testing.T) {
	offset := len(captureSourcePrefix)
	for name, mutate := range map[string]func(*PDU){
		"duplicate":                   func(p *PDU) { p.AddAttribute(p.Attributes[0]) },
		"version":                     func(p *PDU) { p.Attributes[0].Value[offset+1] = 2 },
		"subtype":                     func(p *PDU) { p.Attributes[0].Value[offset] = 2 },
		"flags":                       func(p *PDU) { p.Attributes[0].Value[offset+2] = 2 },
		"noncanonical-unknown-domain": func(p *PDU) { p.Attributes[0].Value[offset+2] = 0 },
		"length":                      func(p *PDU) { binary.BigEndian.PutUint16(p.Attributes[0].Value[offset+3:], 60000) },
		"empty-node":                  func(p *PDU) { binary.BigEndian.PutUint16(p.Attributes[0].Value[offset+3:], 0) },
		"utf8":                        func(p *PDU) { p.Attributes[0].Value[captureSourceHeaderSize] = 0xff },
		"truncated":                   func(p *PDU) { p.Attributes[0].Value = p.Attributes[0].Value[:len(p.Attributes[0].Value)-1] },
		"header-only":                 func(p *PDU) { p.Attributes[0].Value = p.Attributes[0].Value[:len(captureSourcePrefix)] },
		"trailing":                    func(p *PDU) { p.Attributes[0].Value = append(p.Attributes[0].Value, 0) },
		"oversize": func(p *PDU) {
			p.Attributes[0].Value = append(p.Attributes[0].Value, make([]byte, MaxCaptureSourceAttributeBytes)...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			product := sourceProduct(t, "hunter", "eth0", 9, true)
			mutate(product)
			_, available, err := DecodeCaptureSource(product)
			require.ErrorIs(t, err, ErrInvalidCaptureSourceAttribute)
			require.False(t, available)
		})
	}
	for _, input := range []struct {
		node, intf string
		domain     uint32
		known      bool
	}{
		{"", "eth0", 0, false}, {"node", "", 0, false}, {"node", "eth0", 1, false},
		{strings.Repeat("n", 4097), "eth0", 0, false}, {"node", strings.Repeat("i", 4097), 0, false}, {"\xff", "eth0", 0, false},
	} {
		_, err := types.NewCaptureSource(input.node, input.intf, input.domain, input.known)
		require.Error(t, err)
	}
}

func TestCaptureSourceProductBounds(t *testing.T) {
	p := sourceProduct(t, "hunter", "eth0", 0, false)
	p.SetPayload([]byte("payload"))
	wire, err := p.MarshalBinary()
	require.NoError(t, err)
	for _, malformed := range [][]byte{wire[:3], wire[:len(wire)-1], append(append([]byte(nil), wire...), 0)} {
		_, _, err := DecodeProductCaptureSource(malformed)
		require.Error(t, err)
	}
	// A TLV length crossing the header boundary must not consume payload bytes.
	binary.BigEndian.PutUint16(wire[HeaderMinSize+2:], uint16(len(p.Attributes[0].Value)+1))
	_, _, err = DecodeProductCaptureSource(wire)
	require.Error(t, err)
}

func captureSourcePacket() *types.PacketDisplay {
	return &types.PacketDisplay{NodeID: "hunter-a", Interface: "eth0", ObservationDomainKnown: true, Timestamp: time.Unix(100, 123000000), RawData: []byte("media"), VoIPData: &types.VoIPMetadata{IsRTP: true, SSRC: 7, CallID: "source-call"}}
}

func TestCaptureSourceEncodersValidateBeforeSequence(t *testing.T) {
	for _, kind := range []string{"sip", "rtp-call", "rtp-noncall", "raw-ip", "deferred"} {
		t.Run(kind, func(t *testing.T) {
			sequencer := NewSequencer(8)
			x2 := NewX2EncoderWithSequencer(sequencer, "domain", "processor")
			x3 := NewX3EncoderWithSequencer(sequencer, "domain", "processor")
			x2.SetCaptureSourceMetadata(true)
			x3.SetCaptureSourceMetadata(true)
			packet := captureSourcePacket()
			xid := uuid.New()
			if kind == "sip" {
				packet.VoIPData.IsRTP = false
				packet.VoIPData.RawSIP = []byte("INVITE sip:bob@example.invalid SIP/2.0\r\nCall-ID: source-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
			}
			if kind == "rtp-noncall" {
				packet.VoIPData.CallID = ""
			}
			if kind == "raw-ip" {
				packet.RawData[0] = 0x45
			}
			encode := func() (*PDU, error) {
				switch kind {
				case "sip":
					return x2.EncodeIRI(packet, xid)
				case "raw-ip":
					return x3.EncodeRawIPCC(packet, xid, "target")
				case "deferred":
					p, _, err := x3.EncodeCCDeferred(packet, xid, nil)
					return p, err
				default:
					return x3.EncodeCC(packet, xid)
				}
			}
			packet.Interface = ""
			_, err := encode()
			require.ErrorIs(t, err, types.ErrInvalidCaptureSource)
			require.Zero(t, sequencer.Len())
			packet.Interface = "eth0"
			for index, node := range []string{"hunter-a", "hunter-b"} {
				packet.NodeID = node
				product, err := encode()
				require.NoError(t, err)
				source, available, err := DecodeCaptureSource(product)
				require.NoError(t, err)
				require.True(t, available)
				require.Equal(t, node, source.NodeID())
				require.Equal(t, "processor", string(FindAttribute(product.Attributes, AttrIPID).Value))
				sequence := uint32(index)
				if kind == "deferred" {
					sequence = 0
				}
				require.Equal(t, sequence, binary.BigEndian.Uint32(FindAttribute(product.Attributes, AttrSequenceNumber).Value))
				require.Equal(t, NewAttributeBuilder().Timestamp(packet.Timestamp).Value, FindAttribute(product.Attributes, AttrTimestamp).Value)
			}
		})
	}
}

func TestCaptureSourceDeferredProductIsFrozenBeforeStamp(t *testing.T) {
	encoder := NewX3EncoderWithSequencer(nil, "domain", "processor")
	encoder.SetCaptureSourceMetadata(true)
	packet := captureSourcePacket()
	product, deferred, err := encoder.EncodeCCDeferred(packet, uuid.New(), nil)
	require.NoError(t, err)
	packet.NodeID, packet.Interface, packet.ObservationDomain = "hunter-b", "eth1", 42
	wire, err := product.MarshalBinary()
	require.NoError(t, err)
	before := append([]byte(nil), FindAttribute(product.Attributes, AttrProprietary).Value...)
	sequence, err := deferred.Allocate()
	require.NoError(t, err)
	require.NoError(t, StampProductSequence(wire, deferred.Context(), sequence))
	var decoded PDU
	require.NoError(t, decoded.UnmarshalBinary(wire))
	require.Equal(t, before, FindAttribute(decoded.Attributes, AttrProprietary).Value)
	source, available, err := DecodeProductCaptureSource(wire)
	require.NoError(t, err)
	require.True(t, available)
	require.Equal(t, "hunter-a", source.NodeID())
}

func TestRADIUSCaptureSource(t *testing.T) {
	sequencer := NewSequencer(8)
	encoder := NewRADIUSEncoder(sequencer, "domain", "processor", "processor")
	encoder.SetCaptureSourceMetadata(true)
	observation := radiusEncoderObservation(t)
	_, err := encoder.Encode(observation, goldenXID, 42)
	require.ErrorIs(t, err, types.ErrInvalidCaptureSource)
	require.Zero(t, sequencer.Len())
	observation.Scope.SourceID = "eth0"
	for index, node := range []string{"hunter-a", "hunter-b"} {
		observation.Scope.OriginNodeID = node
		product, err := encoder.Encode(observation, goldenXID, 42)
		require.NoError(t, err)
		source, available, err := DecodeCaptureSource(product)
		require.NoError(t, err)
		require.True(t, available)
		require.Equal(t, node, source.NodeID())
		_, known := source.ObservationDomain()
		require.False(t, known)
		require.Equal(t, uint32(index), binary.BigEndian.Uint32(FindAttribute(product.Attributes, AttrSequenceNumber).Value))
	}
}

func FuzzDecodeProductCaptureSource(f *testing.F) {
	f.Add([]byte{})
	product := NewX3RTPPDU(uuid.Nil, 1)
	source, _ := types.NewCaptureSource("hunter", "eth0", 0, true)
	attr, _ := EncodeCaptureSource(source)
	product.AddAttribute(attr)
	wire, _ := product.MarshalBinary()
	f.Add(wire)
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = DecodeProductCaptureSource(data) })
}

func TestCaptureSourceWireVector(t *testing.T) {
	// Independent version-1 vector: namespace+NUL, source subtype, version,
	// domain-known flag, two one-byte identifiers, domain 0x01020304, "h", "e".
	wire, err := hex.DecodeString("6c697070796361742e636170747572655f736f757263650001010100010001010203046865")
	require.NoError(t, err)
	source, err := types.NewCaptureSource("h", "e", 0x01020304, true)
	require.NoError(t, err)
	attribute, err := EncodeCaptureSource(source)
	require.NoError(t, err)
	require.Equal(t, wire, attribute.Value)
	product := NewX2SIPPDU(uuid.Nil, 1)
	product.AddAttribute(TLVAttribute{Type: AttrProprietary, Value: wire})
	decoded, available, err := DecodeCaptureSource(product)
	require.NoError(t, err)
	require.True(t, available)
	require.Equal(t, source, decoded)
}
