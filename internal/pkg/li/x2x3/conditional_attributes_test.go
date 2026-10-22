package x2x3

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProductionEncodersDoNotRepeatAttributesFiveThroughSixteen(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, name := range []string{"sip_x2", "rtp_x3", "radius_x2"} {
			t.Run(name+"/"+family, func(t *testing.T) {
				pkt := conformancePacket(goldenTS, name == "rtp_x3")
				observation := radiusEncoderObservation(t)
				if family == "ipv6" {
					pkt.SrcIP, pkt.DstIP = "2001:db8::1", "2001:db8::2"
					observation.Endpoints.IPFamily = 6
					observation.Endpoints.Source = netip.MustParseAddrPort("[2001:db8::1]:40000")
					observation.Endpoints.Destination = netip.MustParseAddrPort("[2001:db8::2]:1812")
				}
				var pdu *PDU
				var err error
				switch name {
				case "sip_x2":
					pdu, err = NewX2EncoderWithSequencer(nil, "synthetic-domain", "synthetic-nf").EncodeIRI(pkt, goldenXID)
				case "rtp_x3":
					pdu, err = NewX3EncoderWithSequencer(nil, "synthetic-domain", "synthetic-nf").EncodeCC(pkt, goldenXID)
				case "radius_x2":
					pdu, err = NewRADIUSEncoder(nil, "synthetic-domain", "synthetic-nf", "synthetic-poi").Encode(observation, goldenXID, goldenCorr)
				}
				require.NoError(t, err)
				wire, err := pdu.MarshalBinary()
				require.NoError(t, err)
				var decoded PDU
				require.NoError(t, decoded.UnmarshalBinary(wire))
				for typ := AttributeType(5); typ <= 16; typ++ {
					require.LessOrEqual(t, len(FindAllAttributes(decoded.Attributes, typ)), 1, "attribute type %d repeated", typ)
				}
				required := []AttributeType{AttrDomainID, AttrNFID, AttrIPID, AttrTimestamp, AttrSequenceNumber, AttrSourcePort, AttrDestPort}
				if family == "ipv4" {
					required = append(required, AttrSourceIPv4, AttrDestIPv4)
				} else {
					required = append(required, AttrSourceIPv6, AttrDestIPv6)
				}
				if name == "radius_x2" {
					required = append(required, AttrIPProtocol)
				}
				for _, typ := range required {
					require.Len(t, FindAllAttributes(decoded.Attributes, typ), 1, "configured attribute type %d missing", typ)
				}
			})
		}
	}
}

func TestAttributeLookupPreservesRepeatedValuesAndOrder(t *testing.T) {
	for _, typ := range []AttributeType{AttrTimestamp, AttrProprietary, AttrMatchedTargetIdentifier, AttrOtherTargetIdentifier} {
		attrs := []TLVAttribute{
			{Type: AttrSourcePort, Value: []byte{0x13, 0xc4}},
			{Type: typ, Value: []byte("first")},
			{Type: AttrDestPort, Value: []byte{0x13, 0xc4}},
			{Type: typ, Value: []byte("second")},
			{Type: typ, Value: []byte("third")},
		}
		first := FindAttribute(attrs, typ)
		require.Same(t, &attrs[1], first)
		require.Equal(t, []byte("first"), first.Value)
		require.Equal(t, []TLVAttribute{attrs[1], attrs[3], attrs[4]}, FindAllAttributes(attrs, typ))
		require.Len(t, attrs, 5, "lookup must not deduplicate or modify product")
	}
}
