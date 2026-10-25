package events

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSSHProducerOwnsProvenanceAndTypedNilIsRejected(t *testing.T) {
	p, err := NewOfflineProducer("sensor", OfflineSession{InputIdentity: "capture", AnalysisProfile: "ssh"})
	require.NoError(t, err)
	original := NewSSHEvent(Envelope{Provenance: SourceProvenance{ProcessorNodeIDs: []string{"relay"}}})
	assigned := p.Assign(&original).(SSHEvent)
	require.True(t, HasValidDeliveryIdentity(assigned.Envelope()))
	assigned.EventEnvelope.Provenance.ProcessorNodeIDs[0] = "changed"
	require.Equal(t, "relay", original.Envelope().Provenance.ProcessorNodeIDs[0])
	require.Zero(t, original.Envelope().EventSequence)
	require.True(t, isNilEvent((*SSHEvent)(nil)))
	d, err := NewDispatcher(Config{Producer: p, QueueSize: 1, SinkQueueSize: 1})
	require.NoError(t, err)
	require.Nil(t, d.AssignIdentity((*SSHEvent)(nil)))
}
