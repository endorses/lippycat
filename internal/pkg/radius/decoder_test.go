package radius

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func decoderPacket(code byte, attributes ...[]byte) []byte {
	packet := make([]byte, 20)
	packet[0], packet[1] = code, 237
	for i := 4; i < 20; i++ {
		packet[i] = byte(i)
	}
	for _, attribute := range attributes {
		packet = append(packet, attribute...)
	}
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	return packet
}

func decoderAVP(kind byte, value []byte) []byte {
	return append([]byte{kind, byte(len(value) + 2)}, value...)
}

func decoderVSA(inner ...byte) []byte {
	return decoderAVP(26, append([]byte{0, 0, 13, 233}, inner...))
}

func TestDecodePreservesOwnedMessage(t *testing.T) {
	attributes := [][]byte{
		decoderAVP(1, []byte("Alice@example.test")),
		decoderAVP(250, []byte{0xff, 0, 0x80}),
		decoderAVP(1, []byte{0xff, 0}),
		{251, 2}, {1, 2},
		decoderVSA(1, 3, 'a', 99, 2, 1, 3, 'b'),
		decoderAVP(26, []byte{0, 0, 0, 9, 0xff}),
	}
	for _, code := range []byte{1, 2, 3, 4, 5, 11} {
		wire := decoderPacket(code, attributes...)
		original := bytes.Clone(wire)
		// Even padding taking UDP beyond 4096 is excluded before gopacket.
		wire = append(wire, make([]byte, 5000)...)
		message, err := Decode(wire)
		require.NoError(t, err)
		require.Equal(t, original, message.Raw)
		require.Equal(t, code, message.Code)
		require.Equal(t, uint8(237), message.Identifier)
		require.Equal(t, original[4:20], message.Authenticator[:])
		require.Len(t, message.Attributes, len(attributes))
		for index, attribute := range attributes {
			require.Equal(t, attribute, message.Attributes[index].Raw)
		}
		require.Equal(t, uint32(3561), message.Attributes[5].VendorID)
		require.Len(t, message.Attributes[5].VendorAttributes, 3)
		require.Equal(t, []byte{'b'}, message.Attributes[5].VendorAttributes[2].Value)
		require.Nil(t, message.Attributes[6].VendorAttributes)
		clear(wire)
		require.Equal(t, original, message.Raw)
		require.Equal(t, []byte("Alice@example.test"), message.Attributes[0].Value)
	}
}

func TestDecodeRejectsMalformedWithoutPartialIdentity(t *testing.T) {
	badAttributes := map[string][]byte{
		"missing length": {250}, "zero length": {250, 0}, "one length": {250, 1},
		"overrun": {250, 5, 1}, "vendor short": decoderAVP(26, []byte{0, 0, 13}),
		"vendor empty":      decoderAVP(26, []byte{0, 0, 13, 233}),
		"vendor high octet": decoderAVP(26, []byte{1, 0, 0, 9, 1}),
		"inner short":       decoderVSA(1), "inner zero": decoderVSA(1, 0),
		"inner one": decoderVSA(1, 1), "inner overrun": decoderVSA(1, 4, 'a'),
		"inner unknown overrun": decoderVSA(1, 3, 'a', 99, 5, 0),
		"inner unknown tail":    decoderVSA(1, 3, 'a', 99),
		"circuit empty":         decoderVSA(1, 2),
		"circuit oversized":     decoderVSA(append([]byte{1, 66}, make([]byte, 64)...)...),
		"NAS IPv4 short":        decoderAVP(4, []byte{1, 2, 3}),
		"NAS IPv6 short":        decoderAVP(95, make([]byte, 15)),
	}
	for name, attribute := range badAttributes {
		t.Run(name, func(t *testing.T) {
			message, err := Decode(decoderPacket(1, decoderAVP(1, []byte("alice")), attribute))
			require.ErrorIs(t, err, ErrMalformed)
			require.Nil(t, message)
		})
	}
	valid := decoderPacket(1, decoderAVP(1, []byte("alice")))
	for size := 0; size < len(valid); size++ {
		message, err := Decode(valid[:size])
		require.ErrorIs(t, err, ErrMalformed)
		require.Nil(t, message)
	}
	for _, length := range []uint16{0, 1, 19, 4097, 65535} {
		wire := bytes.Clone(valid)
		binary.BigEndian.PutUint16(wire[2:4], length)
		message, err := Decode(wire)
		require.ErrorIs(t, err, ErrMalformed)
		require.Nil(t, message)
	}
}

func TestDecodeCodeAndLengthBoundaries(t *testing.T) {
	for code := 0; code <= 255; code++ {
		message, err := Decode(decoderPacket(byte(code)))
		switch code {
		case 1, 2, 3, 4, 5, 11:
			require.NoError(t, err)
			require.Len(t, message.Raw, 20)
		default:
			require.ErrorIs(t, err, ErrUnsupported)
			require.Nil(t, message)
		}
	}
	// 2038 empty AVPs exactly fill the 4096-byte maximum.
	var avps [][]byte
	for i := 0; i < (4096-20)/2; i++ {
		avps = append(avps, []byte{250, 2})
	}
	message, err := Decode(decoderPacket(4, avps...))
	require.NoError(t, err)
	require.Len(t, message.Raw, 4096)
	require.Len(t, message.Attributes, 2038)
	_, err = Decode(decoderPacket(1, decoderAVP(4, []byte{192, 0, 2, 1}), decoderAVP(95, make([]byte, 16)), decoderVSA(append([]byte{1, 65}, make([]byte, 63)...)...)))
	require.NoError(t, err)
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add(decoderPacket(1, decoderAVP(1, []byte("alice"))))
	f.Add(decoderPacket(4, decoderVSA(1, 3, 'a', 99, 2)))
	f.Add(decoderPacket(1, decoderVSA(1, 3, 'a', 99)))
	f.Add(decoderPacket(11, []byte{250, 2}))
	f.Fuzz(func(t *testing.T, wire []byte) {
		message, err := Decode(wire)
		if err != nil {
			if message != nil {
				t.Fatal("invalid input exposed partial attributes")
			}
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if int(message.Length) < 20 || int(message.Length) > 4096 || int(message.Length) > len(wire) {
			t.Fatal("invalid accepted length")
		}
		if !bytes.Equal(message.Raw, wire[:message.Length]) {
			t.Fatal("message bytes changed")
		}
		// Independently rebuild only from preserved AVPs to detect lost,
		// concatenated, or reordered instances, including zero-value AVPs.
		rebuilt := bytes.Clone(message.Raw[:20])
		for _, attribute := range message.Attributes {
			if len(attribute.Raw) < 2 || int(attribute.Raw[1]) != len(attribute.Raw) || !bytes.Equal(attribute.Raw[2:], attribute.Value) {
				t.Fatal("invalid accepted AVP")
			}
			rebuilt = append(rebuilt, attribute.Raw...)
			if attribute.VendorID == 3561 {
				inner := []byte{}
				for _, vendor := range attribute.VendorAttributes {
					if len(vendor.Raw) < 2 || int(vendor.Raw[1]) != len(vendor.Raw) || !bytes.Equal(vendor.Raw[2:], vendor.Value) {
						t.Fatal("invalid accepted vendor AVP")
					}
					if vendor.Type == 1 && (len(vendor.Value) < 1 || len(vendor.Value) > 63) {
						t.Fatal("false circuit identity")
					}
					inner = append(inner, vendor.Raw...)
				}
				if !bytes.Equal(inner, attribute.Value[4:]) {
					t.Fatal("lost vendor bytes")
				}
			}
		}
		if !bytes.Equal(rebuilt, message.Raw) {
			t.Fatal("lost attribute bytes")
		}
		owned := bytes.Clone(message.Raw)
		clear(wire)
		if !bytes.Equal(message.Raw, owned) {
			t.Fatal("borrowed capture buffer")
		}
	})
}
