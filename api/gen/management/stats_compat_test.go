package management

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type legacyHunterStats struct {
	packetsDropped     uint64
	regularBufferDrops uint64
	sipBufferDrops     uint64
	batchChannelDrops  uint64
}

func TestHunterStatsNamedLossCountersWireRoundTrip(t *testing.T) {
	want := &HunterHeartbeat{
		HunterId: "hunter-test",
		Stats: &HunterStats{
			PacketsDropped:            9,
			CaptureBufferRegularDrops: 4,
			CaptureBufferSipDrops:     2,
			BatchChannelDrops:         3,
			CaptureBufferSipDemotions: 5,
			CaptureBufferRegularLen:   6, CaptureBufferRegularCapacity: 16,
			CaptureBufferSipLen: 7, CaptureBufferSipCapacity: 17,
			CaptureBufferOutputLen: 8, CaptureBufferOutputCapacity: 18,
		},
	}

	payload, err := proto.Marshal(want)
	require.NoError(t, err)

	var got HunterHeartbeat
	require.NoError(t, proto.Unmarshal(payload, &got))
	require.True(t, proto.Equal(want, &got))
	require.Equal(t, got.Stats.PacketsDropped,
		got.Stats.CaptureBufferRegularDrops+got.Stats.CaptureBufferSipDrops+got.Stats.BatchChannelDrops)
	require.NotEqual(t, got.Stats.PacketsDropped,
		got.Stats.CaptureBufferRegularDrops+got.Stats.CaptureBufferSipDrops+got.Stats.BatchChannelDrops+got.Stats.CaptureBufferSipDemotions)

	legacy, err := decodeLegacyHunterHeartbeat(payload)
	require.NoError(t, err)
	require.Equal(t, legacyHunterStats{
		packetsDropped:     9,
		regularBufferDrops: 4,
		sipBufferDrops:     2,
		batchChannelDrops:  3,
	}, legacy, "a frozen old reader must preserve known fields while ignoring fields 26-32")
}

func TestHunterStatsLegacyPayloadDefaultsPriorityPressureToZero(t *testing.T) {
	legacyStats := appendLegacyVarintFields(nil,
		4, 3,
		10, 1,
		11, 1,
		12, 1,
	)
	legacyPayload := protowire.AppendTag(nil, 4, protowire.BytesType)
	legacyPayload = protowire.AppendBytes(legacyPayload, legacyStats)

	var got HunterHeartbeat
	require.NoError(t, proto.Unmarshal(legacyPayload, &got))
	require.Equal(t, uint64(3), got.Stats.PacketsDropped)
	require.Equal(t, uint64(1), got.Stats.CaptureBufferRegularDrops)
	require.Equal(t, uint64(1), got.Stats.CaptureBufferSipDrops)
	require.Equal(t, uint64(1), got.Stats.BatchChannelDrops)
	require.Zero(t, got.Stats.CaptureBufferSipDemotions)
	require.Zero(t, got.Stats.CaptureBufferRegularLen)
	require.Zero(t, got.Stats.CaptureBufferRegularCapacity)
	require.Zero(t, got.Stats.CaptureBufferSipLen)
	require.Zero(t, got.Stats.CaptureBufferSipCapacity)
	require.Zero(t, got.Stats.CaptureBufferOutputLen)
	require.Zero(t, got.Stats.CaptureBufferOutputCapacity)
}

// decodeLegacyHunterHeartbeat is a frozen reader for the pre-priority-pressure
// wire contract. It knows HunterHeartbeat.stats (field 4) and only HunterStats
// fields that existed before the additions at 26-32.
func decodeLegacyHunterHeartbeat(payload []byte) (legacyHunterStats, error) {
	for len(payload) > 0 {
		num, typ, n := protowire.ConsumeTag(payload)
		if n < 0 {
			return legacyHunterStats{}, protowire.ParseError(n)
		}
		payload = payload[n:]
		if num == 4 && typ == protowire.BytesType {
			stats, consumed := protowire.ConsumeBytes(payload)
			if consumed < 0 {
				return legacyHunterStats{}, protowire.ParseError(consumed)
			}
			return decodeLegacyHunterStats(stats)
		}
		consumed := protowire.ConsumeFieldValue(num, typ, payload)
		if consumed < 0 {
			return legacyHunterStats{}, protowire.ParseError(consumed)
		}
		payload = payload[consumed:]
	}
	return legacyHunterStats{}, fmt.Errorf("legacy HunterHeartbeat payload has no stats field")
}

func decodeLegacyHunterStats(payload []byte) (legacyHunterStats, error) {
	var stats legacyHunterStats
	for len(payload) > 0 {
		num, typ, n := protowire.ConsumeTag(payload)
		if n < 0 {
			return legacyHunterStats{}, protowire.ParseError(n)
		}
		payload = payload[n:]
		if typ == protowire.VarintType && num >= 1 && num <= 25 {
			value, consumed := protowire.ConsumeVarint(payload)
			if consumed < 0 {
				return legacyHunterStats{}, protowire.ParseError(consumed)
			}
			switch num {
			case 4:
				stats.packetsDropped = value
			case 10:
				stats.regularBufferDrops = value
			case 11:
				stats.sipBufferDrops = value
			case 12:
				stats.batchChannelDrops = value
			}
			payload = payload[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(num, typ, payload)
		if consumed < 0 {
			return legacyHunterStats{}, protowire.ParseError(consumed)
		}
		payload = payload[consumed:]
	}
	return stats, nil
}

func appendLegacyVarintFields(payload []byte, fields ...uint64) []byte {
	for i := 0; i < len(fields); i += 2 {
		payload = protowire.AppendTag(payload, protowire.Number(fields[i]), protowire.VarintType)
		payload = protowire.AppendVarint(payload, fields[i+1])
	}
	return payload
}
