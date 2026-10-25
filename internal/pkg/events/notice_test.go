package events

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNoticeIdentityReservationAndOwnership(t *testing.T) {
	producer, err := NewOfflineProducer("sensor", OfflineSession{InputIdentity: "capture", AnalysisProfile: "notice-policy"})
	require.NoError(t, err)
	dispatcher, err := NewDispatcher(Config{QueueSize: 4, SinkQueueSize: 4, Producer: producer})
	require.NoError(t, err)
	notice := NewNoticeEvent(Envelope{Timestamp: time.Unix(42, 0), Provenance: SourceProvenance{ProcessorNodeIDs: []string{"processor"}}})
	notice.DNS = &DNSNoticeEvidence{Domain: "example.test", SourceIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	notice.Evidence = []NoticeEvidenceReference{{NodeID: "sensor", UID: "flow", Timestamp: time.Unix(42, 0)}}
	assigned := dispatcher.AssignIdentity(&notice).(NoticeEvent)
	require.True(t, HasValidDeliveryIdentity(assigned.Envelope()))
	require.Equal(t, assigned, dispatcher.AssignIdentity(assigned))
	require.Zero(t, notice.Envelope().EventSequence)
	assigned.DNS.SourceIPs[0] = netip.Addr{}
	assigned.Evidence[0].UID = "other"
	assigned.EventEnvelope.Provenance.ProcessorNodeIDs[0] = "other"
	require.True(t, notice.DNS.SourceIPs[0].IsValid())
	require.Equal(t, "flow", notice.Evidence[0].UID)
	require.Equal(t, "processor", notice.Envelope().Provenance.ProcessorNodeIDs[0])
	require.Nil(t, dispatcher.AssignIdentity((*NoticeEvent)(nil)))
	require.True(t, isNilEvent((*NoticeEvent)(nil)))
}
