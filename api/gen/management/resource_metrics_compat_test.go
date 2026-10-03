package management

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestResourceMetricsOldAndNewWireCompatibility(t *testing.T) {
	// Model the established wire fields independently of the current generated
	// descriptor, so accidentally changing their types/numbers fails this test.
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("legacy_resource_metrics.proto"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("HunterStats"), Field: []*descriptorpb.FieldDescriptorProto{
			{Name: proto.String("cpu_percent"), Number: proto.Int32(7), Type: descriptorpb.FieldDescriptorProto_TYPE_FLOAT.Enum()},
			{Name: proto.String("memory_rss_bytes"), Number: proto.Int32(8), Type: descriptorpb.FieldDescriptorProto_TYPE_UINT64.Enum()},
			{Name: proto.String("memory_limit_bytes"), Number: proto.Int32(9), Type: descriptorpb.FieldDescriptorProto_TYPE_UINT64.Enum()},
		}}},
	}, nil)
	require.NoError(t, err)
	oldDescriptor := file.Messages().ByName("HunterStats")
	want := &HunterStats{CpuPercent: 240, MemoryRssBytes: 750, MemoryLimitBytes: 1000, CpuCapacityCores: 3.5, MetricsSampleTimeNs: 123456789}
	wire, err := proto.Marshal(want)
	require.NoError(t, err)
	old := dynamicpb.NewMessage(oldDescriptor)
	require.NoError(t, proto.Unmarshal(wire, old))
	require.Equal(t, float32(240), float32(old.Get(oldDescriptor.Fields().ByNumber(7)).Float()), "old clients retain per-core percentage units")
	require.Equal(t, uint64(750), old.Get(oldDescriptor.Fields().ByNumber(8)).Uint())
	require.Equal(t, uint64(1000), old.Get(oldDescriptor.Fields().ByNumber(9)).Uint())
	forwarded, err := proto.Marshal(old)
	require.NoError(t, err)
	var roundTrip HunterStats
	require.NoError(t, proto.Unmarshal(forwarded, &roundTrip))
	require.True(t, proto.Equal(want, &roundTrip), "a transparent old protobuf forwarder preserves unknown fields")

	// Older senders and intermediaries rebuilding only known fields omit the
	// additions. New readers must retain old metrics and see unknown capacity.
	old.SetUnknown(nil)
	legacyWire, err := proto.Marshal(old)
	require.NoError(t, err)
	var legacy HunterStats
	require.NoError(t, proto.Unmarshal(legacyWire, &legacy))
	require.Equal(t, want.CpuPercent, legacy.CpuPercent)
	require.Equal(t, want.MemoryRssBytes, legacy.MemoryRssBytes)
	require.Equal(t, want.MemoryLimitBytes, legacy.MemoryLimitBytes)
	require.Zero(t, legacy.CpuCapacityCores)
	require.Zero(t, legacy.MetricsSampleTimeNs)
	fields := want.ProtoReflect().Descriptor().Fields()
	require.Equal(t, protoreflect.FieldNumber(38), fields.ByName("cpu_capacity_cores").Number())
	require.Equal(t, protoreflect.FieldNumber(39), fields.ByName("metrics_sample_time_ns").Number())
}
