package offline

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCompactTypedVoIPMatchesFrozenCodec(t *testing.T) {
	full := types.VoIPMetadata{
		CallID: "call\x00\xff", Method: "INVITE", CSeqMethod: "ACK", Status: -123,
		From: "from", To: "to", FromTag: "from-tag", ToTag: "to-tag", User: "user", ContentType: "application/sdp", Body: "body\xfe",
		Headers: map[string]string{"z-last": "last", "a-first": "first", "\xff": "\x00"}, RawSIP: []byte{0, 1, 128, 255}, IMSI: "imsi", IMEI: "imei",
		AccessNetworkInfo: &types.AccessNetworkInfo{AccessType: "access", BSSID: "bssid", CellID: "cell", LocalIP: "local", Parameters: map[string]string{"z": "z", "a": "a"}},
		VisitedNetworkID:  "visited", IsRTP: true, SSRC: math.MaxUint32, PayloadType: math.MaxUint8, SequenceNum: math.MaxUint16, SeqNumber: 13, Timestamp: 42, Codec: "codec", MergeFromCallID: "merge",
	}
	empty := types.VoIPMetadata{Headers: map[string]string{}, RawSIP: []byte{}, AccessNetworkInfo: &types.AccessNetworkInfo{Parameters: map[string]string{}}}
	nilContainers := types.VoIPMetadata{AccessNetworkInfo: &types.AccessNetworkInfo{}}
	for _, voip := range []*types.VoIPMetadata{nil, {}, &full, &empty, &nilContainers} {
		for _, mask := range []uint8{0, 1, 31, 255} {
			value := compactOverrides{Mask: mask, Metadata: compactMetadata{VoIP: voip}}
			for _, mixed := range []bool{false, true} {
				if mixed {
					value.Metadata.HTTP = &types.HTTPMetadata{Headers: map[string]string{"test": "value"}}
				}
				for max := uint64(0); max < 3000; max += 17 {
					want, wantErr := encodeCompactValue(value, max)
					got, err := encodeCompactOverrides(value, max)
					require.Equal(t, wantErr == nil, err == nil, "mask=%d mixed=%v max=%d", mask, mixed, max)
					if wantErr != nil {
						require.EqualError(t, err, wantErr.Error())
					}
					require.Equal(t, want, got)
				}
				want, err := encodeCompactValue(value, 8192)
				require.NoError(t, err)
				got, err := encodeCompactOverrides(value, 8192)
				require.NoError(t, err)
				require.Equal(t, want, got)
				var decoded compactOverrides
				require.NoError(t, decodeCompactValue(got, &decoded, 8192))
				require.Equal(t, value, decoded)
				_, wantErr := encodeCompactValue(value, math.MaxUint64)
				_, err = encodeCompactOverrides(value, math.MaxUint64)
				require.EqualError(t, err, wantErr.Error())
			}
		}
	}
}

func BenchmarkCompactTypedVoIP(b *testing.B) {
	for _, sip := range []bool{false, true} {
		p := &types.VoIPMetadata{CallID: "call", IsRTP: true, SSRC: 12345, SequenceNum: 32000, Timestamp: 10240, Codec: "PCMU"}
		if sip {
			p.IsRTP = false
			p.Method = "INVITE"
			p.Headers = map[string]string{"Via": "SIP/2.0/UDP host.test", "From": "alice@example.test", "To": "bob@example.test"}
			p.RawSIP = bytes.Repeat([]byte("INVITE sip:bob@example.test\r\n"), 32)
		}
		value := compactOverrides{Mask: 1, Metadata: compactMetadata{VoIP: p}}
		for _, typed := range []bool{false, true} {
			b.Run(fmt.Sprintf("sip%v/typed%v", sip, typed), func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					var err error
					if typed {
						_, err = encodeCompactOverrides(value, 1<<20)
					} else {
						_, err = encodeCompactValue(value, 1<<20)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
