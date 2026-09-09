//go:build (processor || tap || all) && li

package processor

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func radiusScopeMatcher(t *testing.T, task *li.InterceptTask) radiusPOIMatcher {
	t.Helper()
	filters := li.NewFilterManager(nil)
	ids, err := filters.CreateFiltersForTask(task)
	require.NoError(t, err)
	group, ok := filters.LookupRADIUSGroup(ids[0])
	require.True(t, ok)
	return radiusPOIMatcher{group}
}

func radiusScopeCapture(t *testing.T, origin string) *radius.CaptureProcessor {
	t.Helper()
	capture, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: origin, SourceID: "eth0", OperatorScope: "operator", ProfileRevision: "v1"})
	require.NoError(t, err)
	t.Cleanup(capture.Close)
	return capture
}

func radiusScopeObserve(t *testing.T, capture *radius.CaptureProcessor, matcher radiusPOIMatcher, index int, sourceID string, at time.Time) *radius.Observation {
	t.Helper()
	fixture := radiusOutputFixtures(t)[index]
	packet := gopacket.NewPacket(fixture.Data, layers.LinkType(fixture.LinkType), gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: at, CaptureLength: int(fixture.CaptureLength), Length: int(fixture.OriginalLength)}
	observation := capture.Process(packet, layers.LinkType(fixture.LinkType), sourceID, matcher)
	require.NotNil(t, observation)
	return observation
}

// A wire round trip must preserve evidence while trust is supplied only by the
// authenticated ingress. The caller models that established direct-source trust.
func radiusScopeBatch(t *testing.T, observation *radius.Observation) *source.PacketBatch {
	t.Helper()
	packet := &data.CapturedPacket{Data: observation.Packet, TimestampNs: observation.Capture.Timestamp.UnixNano(), CaptureLength: uint32(observation.Capture.CapturedLength), OriginalLength: uint32(observation.Capture.OriginalLength), LinkType: uint32(observation.Capture.LinkType), Radius: grpcadapter.RADIUSToProto(observation)}
	wire, err := proto.Marshal(&data.PacketBatch{HunterId: observation.Scope.OriginNodeID, Packets: []*data.CapturedPacket{packet}})
	require.NoError(t, err)
	restored := new(data.PacketBatch)
	require.NoError(t, proto.Unmarshal(wire, restored))
	batch := source.FromProtoBatch(restored)
	require.False(t, batch.RADIUSSourceTrusted)
	batch.RADIUSSourceTrusted = true
	return batch
}

func TestRADIUSDistributedScopeBoundaries(t *testing.T) {
	for _, boundary := range []string{"other hunter", "other interface", "reconnect", "restart"} {
		t.Run(boundary, func(t *testing.T) {
			p, task, _ := radiusPOIProcessor(t, 16)
			matcher := radiusScopeMatcher(t, task)
			first := radiusScopeCapture(t, "hunter-a")
			now := time.Now()
			request := radiusScopeObserve(t, first, matcher, 0, "eth0", now)
			require.Len(t, request.Direct, 1)
			p.processBatch(radiusScopeBatch(t, request))
			require.EqualValues(t, 1, p.radiusLIStats.QueueAccepted)
			capture, iface := first, "eth0"
			switch boundary {
			case "other hunter":
				capture = radiusScopeCapture(t, "hunter-b")
			case "other interface":
				iface = "eth1"
			case "reconnect":
				require.NoError(t, first.AdvanceBoundary(now.Add(time.Millisecond)))
			case "restart":
				first.Close()
				capture = radiusScopeCapture(t, "hunter-a")
			}
			response := radiusScopeObserve(t, capture, matcher, 1, iface, now.Add(2*time.Millisecond))
			require.Equal(t, radius.AssociationMissing, response.Association.Status)
			require.Empty(t, response.Inherited)
			if boundary == "reconnect" || boundary == "restart" {
				require.NotEqual(t, request.Scope.Epoch, response.Scope.Epoch)
			}
			p.processBatch(radiusScopeBatch(t, response))
			require.EqualValues(t, 1, p.radiusLIStats.QueueAccepted, "response must not inherit across a scope boundary")
			// A new complete exchange in the new scope can authorize normally.
			current := radiusScopeObserve(t, capture, matcher, 0, iface, now.Add(3*time.Millisecond))
			reply := radiusScopeObserve(t, capture, matcher, 1, iface, now.Add(4*time.Millisecond))
			require.Len(t, current.Direct, 1)
			require.Len(t, reply.Inherited, 1)
			p.processBatch(radiusScopeBatch(t, current))
			p.processBatch(radiusScopeBatch(t, reply))
			require.EqualValues(t, 3, p.radiusLIStats.QueueAccepted)
		})
	}
}

func TestRADIUSDistributedDroppedRequestRetainsCaptureEvidence(t *testing.T) {
	p, task, _ := radiusPOIProcessor(t, 16)
	capture := radiusScopeCapture(t, "hunter-a")
	matcher := radiusScopeMatcher(t, task)
	now := time.Now()
	request := radiusScopeObserve(t, capture, matcher, 0, "eth0", now)
	response := radiusScopeObserve(t, capture, matcher, 1, "eth0", now.Add(time.Millisecond))
	require.Equal(t, request.Capture.ID, response.Association.RequestObservationID)
	require.Len(t, response.Inherited, 1)
	// The request is deliberately dropped before transport. A processor must use
	// current authenticated capture evidence, not require a second correlation cache.
	p.processBatch(radiusScopeBatch(t, response))
	require.EqualValues(t, 1, p.radiusLIStats.QueueAccepted)
	require.NoError(t, p.liManager.DeactivateTask(task.XID))
	p.processBatch(radiusScopeBatch(t, response))
	require.EqualValues(t, 1, p.radiusLIStats.QueueAccepted, "transported evidence cannot outlive task authorization")
}

func TestRADIUSDistributedMissingOrForeignEvidencePreservesOrdinaryOutput(t *testing.T) {
	for _, mutation := range []string{"legacy", "missing evidence", "foreign origin", "foreign interface", "foreign epoch", "untrusted"} {
		t.Run(mutation, func(t *testing.T) {
			p, task, dir := radiusPOIProcessor(t, 16)
			batch, _ := radiusPOIBatch(t, p, task)
			wire, err := batch.ToProtoBatchE()
			require.NoError(t, err)
			for _, packet := range wire.Packets {
				observation, err := grpcadapter.RADIUSFromProto(packet)
				require.NoError(t, err)
				switch mutation {
				case "legacy":
					packet.Radius = nil
				case "missing evidence":
					observation.Direct, observation.Inherited = nil, nil
					packet.Radius = grpcadapter.RADIUSToProto(observation)
				case "foreign origin":
					wire.HunterId = "other-hunter"
				case "foreign interface":
					observation.Scope.SourceID = "other-interface"
					packet.Radius = grpcadapter.RADIUSToProto(observation)
				case "foreign epoch":
					observation.Scope.Epoch[0] ^= 1
					packet.Radius = grpcadapter.RADIUSToProto(observation)
				}
				// Generic LI IDs from older peers must never provide a fallback admission.
				packet.MatchedFilterIds = []string{"li-" + task.XID.String()}
			}
			batch = source.FromProtoBatch(wire)
			batch.RADIUSSourceTrusted = mutation != "untrusted"
			out := p.subscriberManager.Add("scope-ordinary")
			p.processBatch(batch)
			requireRadiusPOIBroadcast(t, out)
			require.Zero(t, p.radiusLIStats.QueueAccepted)
			assertRadiusPOIOrdinary(t, p, dir, 2)
		})
	}
}
