package data

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type legacyBatchStats struct {
	dropped            uint64
	regularBufferDrops uint64
	sipBufferDrops     uint64
	batchChannelDrops  uint64
}

func TestBatchStatsPriorityPressureWireRoundTrip(t *testing.T) {
	want := &PacketBatch{Stats: &BatchStats{
		Dropped: 6, CaptureBufferRegularDrops: 2, CaptureBufferSipDrops: 1, BatchChannelDrops: 3,
		CaptureBufferSipDemotions: 5,
		CaptureBufferRegularLen:   6, CaptureBufferRegularCapacity: 16,
		CaptureBufferSipLen: 7, CaptureBufferSipCapacity: 17,
		CaptureBufferOutputLen: 8, CaptureBufferOutputCapacity: 18,
	}}
	payload, err := proto.Marshal(want)
	require.NoError(t, err)

	var got PacketBatch
	require.NoError(t, proto.Unmarshal(payload, &got))
	require.True(t, proto.Equal(want, &got))
	require.Equal(t, got.Stats.Dropped,
		got.Stats.CaptureBufferRegularDrops+got.Stats.CaptureBufferSipDrops+got.Stats.BatchChannelDrops)

	legacy, err := decodeLegacyPacketBatch(payload)
	require.NoError(t, err)
	require.Equal(t, legacyBatchStats{
		dropped:            6,
		regularBufferDrops: 2,
		sipBufferDrops:     1,
		batchChannelDrops:  3,
	}, legacy, "a frozen old reader must preserve known fields while ignoring fields 8-14")
}

func TestBatchStatsLegacyPayloadDefaultsPriorityPressureToZero(t *testing.T) {
	legacyStats := appendVarintFields(nil,
		3, 6,
		5, 2,
		6, 1,
		7, 3,
	)
	payload := protowire.AppendTag(nil, 5, protowire.BytesType)
	payload = protowire.AppendBytes(payload, legacyStats)

	var got PacketBatch
	require.NoError(t, proto.Unmarshal(payload, &got))
	require.Equal(t, uint64(6), got.Stats.Dropped)
	require.Equal(t, uint64(2), got.Stats.CaptureBufferRegularDrops)
	require.Equal(t, uint64(1), got.Stats.CaptureBufferSipDrops)
	require.Equal(t, uint64(3), got.Stats.BatchChannelDrops)
	require.Zero(t, got.Stats.CaptureBufferSipDemotions)
	require.Zero(t, got.Stats.CaptureBufferRegularLen)
	require.Zero(t, got.Stats.CaptureBufferRegularCapacity)
	require.Zero(t, got.Stats.CaptureBufferSipLen)
	require.Zero(t, got.Stats.CaptureBufferSipCapacity)
	require.Zero(t, got.Stats.CaptureBufferOutputLen)
	require.Zero(t, got.Stats.CaptureBufferOutputCapacity)
}

// decodeLegacyPacketBatch is a frozen reader for the pre-priority-pressure wire
// contract. It deliberately knows only PacketBatch.stats (field 5) and the
// legacy BatchStats fields 1-7, exactly as an old peer would.
func decodeLegacyPacketBatch(payload []byte) (legacyBatchStats, error) {
	for len(payload) > 0 {
		num, typ, n := protowire.ConsumeTag(payload)
		if n < 0 {
			return legacyBatchStats{}, protowire.ParseError(n)
		}
		payload = payload[n:]
		if num == 5 && typ == protowire.BytesType {
			stats, consumed := protowire.ConsumeBytes(payload)
			if consumed < 0 {
				return legacyBatchStats{}, protowire.ParseError(consumed)
			}
			return decodeLegacyBatchStats(stats)
		}
		consumed := protowire.ConsumeFieldValue(num, typ, payload)
		if consumed < 0 {
			return legacyBatchStats{}, protowire.ParseError(consumed)
		}
		payload = payload[consumed:]
	}
	return legacyBatchStats{}, fmt.Errorf("legacy PacketBatch payload has no stats field")
}

func decodeLegacyBatchStats(payload []byte) (legacyBatchStats, error) {
	var stats legacyBatchStats
	for len(payload) > 0 {
		num, typ, n := protowire.ConsumeTag(payload)
		if n < 0 {
			return legacyBatchStats{}, protowire.ParseError(n)
		}
		payload = payload[n:]
		if typ == protowire.VarintType && num >= 1 && num <= 7 {
			value, consumed := protowire.ConsumeVarint(payload)
			if consumed < 0 {
				return legacyBatchStats{}, protowire.ParseError(consumed)
			}
			switch num {
			case 3:
				stats.dropped = value
			case 5:
				stats.regularBufferDrops = value
			case 6:
				stats.sipBufferDrops = value
			case 7:
				stats.batchChannelDrops = value
			}
			payload = payload[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(num, typ, payload)
		if consumed < 0 {
			return legacyBatchStats{}, protowire.ParseError(consumed)
		}
		payload = payload[consumed:]
	}
	return stats, nil
}

func appendVarintFields(payload []byte, fields ...uint64) []byte {
	for i := 0; i < len(fields); i += 2 {
		payload = protowire.AppendTag(payload, protowire.Number(fields[i]), protowire.VarintType)
		payload = protowire.AppendVarint(payload, fields[i+1])
	}
	return payload
}
