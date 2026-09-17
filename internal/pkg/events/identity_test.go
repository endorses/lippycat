package events

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLiveProducerAssignsIdentityBeforeConstruction(t *testing.T) {
	producer, err := newLiveProducer("effective-hunter", strings.NewReader("0123456789abcdef"))
	require.NoError(t, err)

	first := producer.NewDNSEvent(Envelope{NodeID: "requested-hunter"})
	second := producer.NewHTTPEvent(Envelope{})

	require.Equal(t, "effective-hunter", first.Envelope().NodeID)
	require.Equal(t, "requested-hunter", first.Envelope().Provenance.CaptureSource)
	require.Equal(t, "30313233343536373839616263646566", first.Envelope().ProducerSessionID)
	require.Equal(t, uint64(1), first.Envelope().EventSequence)
	require.NotEmpty(t, first.Envelope().EventID)
	require.Equal(t, uint64(2), second.Envelope().EventSequence)
	require.NotEqual(t, first.Envelope().EventID, second.Envelope().EventID)
}

func TestLiveProducerSequenceExhaustionNeverWraps(t *testing.T) {
	const session = "30313233343536373839616263646566"
	_, err := ResumeLiveProducer("node", session, ^uint64(0))
	require.ErrorContains(t, err, "sequence is exhausted")

	producer, err := ResumeLiveProducer("node", session, ^uint64(0)-1)
	require.NoError(t, err)
	last := producer.Assign(NewDNSEvent(Envelope{}))
	require.Equal(t, ^uint64(0), last.Envelope().EventSequence)
	next := producer.Assign(NewDNSEvent(Envelope{}))
	require.Zero(t, next.Envelope().EventSequence)
	require.Empty(t, next.Envelope().EventID)
}

func TestLiveProducerUsesIndependentRandomSessions(t *testing.T) {
	first, err := newLiveProducer("node", strings.NewReader("0123456789abcdef"))
	require.NoError(t, err)
	second, err := newLiveProducer("node", strings.NewReader("fedcba9876543210"))
	require.NoError(t, err)
	require.NotEqual(t, first.SessionID(), second.SessionID())

	_, err = newLiveProducer("node", strings.NewReader("short"))
	require.Error(t, err)
	_, err = newLiveProducer("", strings.NewReader("0123456789abcdef"))
	require.Error(t, err)
}

func TestOfflineProducerIsDeterministicAndOrderSensitive(t *testing.T) {
	config := OfflineSession{InputIdentity: "sha256:input", AnalysisProfile: "events-v1", SourceOrdering: []string{"a.pcap", "b.pcap"}}
	first, err := NewOfflineProducer("offline", config)
	require.NoError(t, err)
	second, err := NewOfflineProducer("offline", config)
	require.NoError(t, err)
	otherNode, err := NewOfflineProducer("other-offline-node", config)
	require.NoError(t, err)

	firstEvent := first.NewSMTPEvent(Envelope{})
	secondEvent := second.NewSMTPEvent(Envelope{})
	require.Equal(t, first.SessionID(), second.SessionID())
	require.Equal(t, first.SessionID(), otherNode.SessionID(), "node ID is a separate delivery identity component")
	require.Equal(t, firstEvent.Envelope().EventID, secondEvent.Envelope().EventID)

	reordered := config
	reordered.SourceOrdering = []string{"b.pcap", "a.pcap"}
	third, err := NewOfflineProducer("offline", reordered)
	require.NoError(t, err)
	require.NotEqual(t, first.SessionID(), third.SessionID())
}

func TestProducerAssignPreservesIdentityOnRetry(t *testing.T) {
	producer, err := NewOfflineProducer("node", OfflineSession{InputIdentity: "input", AnalysisProfile: "v1"})
	require.NoError(t, err)
	first := producer.Assign(NewDNSEvent(Envelope{}))
	retry := producer.Assign(first)
	require.Equal(t, first.Envelope(), retry.Envelope())
	require.Equal(t, uint64(2), producer.NewDNSEvent(Envelope{}).Envelope().EventSequence)
}

func TestProducerReplacesInconsistentIdentity(t *testing.T) {
	producer, err := NewOfflineProducer("node", OfflineSession{InputIdentity: "input", AnalysisProfile: "v1"})
	require.NoError(t, err)
	event := NewDNSEvent(Envelope{NodeID: "node", ProducerSessionID: "stale", EventSequence: 99, EventID: "forged"})
	assigned := producer.Assign(event)
	require.True(t, HasValidDeliveryIdentity(assigned.Envelope()))
	require.Equal(t, producer.SessionID(), assigned.Envelope().ProducerSessionID)
	require.Equal(t, uint64(1), assigned.Envelope().EventSequence)
}

func TestEventIdentityUsesEffectiveProducerNode(t *testing.T) {
	first, err := NewOfflineProducer("processor-a", OfflineSession{InputIdentity: "input", AnalysisProfile: "v1"})
	require.NoError(t, err)
	second, err := NewOfflineProducer("processor-b", OfflineSession{InputIdentity: "input", AnalysisProfile: "v1"})
	require.NoError(t, err)
	one := first.NewDNSEvent(Envelope{NodeID: "hunter"})
	two := second.NewDNSEvent(Envelope{NodeID: "hunter"})
	require.Equal(t, "processor-a", one.Envelope().NodeID)
	require.Equal(t, "hunter", one.Envelope().Provenance.CaptureSource)
	require.NotEqual(t, one.Envelope().EventID, two.Envelope().EventID)
}

func TestOfflineProducerValidatesStableInputs(t *testing.T) {
	_, err := NewOfflineProducer("", OfflineSession{InputIdentity: "input", AnalysisProfile: "v1"})
	require.ErrorContains(t, err, "node ID")
	_, err = NewOfflineProducer("node", OfflineSession{AnalysisProfile: "v1"})
	require.ErrorContains(t, err, "input identity")
	_, err = NewOfflineProducer("node", OfflineSession{InputIdentity: "input"})
	require.ErrorContains(t, err, "analysis profile")
}

func TestLiveProducerReportsRandomSourceFailure(t *testing.T) {
	_, err := newLiveProducer("node", errorReader{})
	require.ErrorContains(t, err, "producer session")
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("random unavailable") }

func TestProducerConstructorsCoverEveryEventKind(t *testing.T) {
	producer, err := NewOfflineProducer("node", OfflineSession{InputIdentity: "input", AnalysisProfile: "v1"})
	require.NoError(t, err)
	events := []Event{
		producer.NewDNSEvent(Envelope{}),
		producer.NewSMTPEvent(Envelope{}),
		producer.NewTLSEvent(Envelope{}),
		producer.NewHTTPEvent(Envelope{}),
		producer.NewConnEvent(Envelope{}),
		producer.NewFileMetadataEvent(Envelope{}),
		producer.NewFileContentEvent(Envelope{}),
	}
	for i, event := range events {
		require.Equal(t, uint64(i+1), event.Envelope().EventSequence)
		require.NotEmpty(t, event.Envelope().EventID)
	}
}

func TestLiveProducerSetKeepsPerSourceIdentity(t *testing.T) {
	set, err := NewLiveProducerSet()
	require.NoError(t, err)
	first := set.Assign(NewDNSEvent(Envelope{NodeID: "hunter-a"}))
	second := set.Assign(NewHTTPEvent(Envelope{NodeID: "hunter-a"}))
	other := set.Assign(NewDNSEvent(Envelope{NodeID: "hunter-b"}))
	require.Equal(t, "hunter-a", first.Envelope().NodeID)
	require.Equal(t, first.Envelope().ProducerSessionID, second.Envelope().ProducerSessionID)
	require.Equal(t, uint64(2), second.Envelope().EventSequence)
	require.NotEqual(t, first.Envelope().ProducerSessionID, other.Envelope().ProducerSessionID)
}

func TestLiveProducerSetRotateStartsFreshSession(t *testing.T) {
	set, err := NewLiveProducerSet()
	require.NoError(t, err)
	first := set.Assign(NewDNSEvent(Envelope{NodeID: "node"}))
	previous, replacement, err := set.Rotate("node")
	require.NoError(t, err)
	require.Equal(t, first.Envelope().ProducerSessionID, previous)
	require.NotEqual(t, previous, replacement)
	second := set.Assign(NewDNSEvent(Envelope{NodeID: "node"}))
	require.Equal(t, replacement, second.Envelope().ProducerSessionID)
	require.Equal(t, uint64(1), second.Envelope().EventSequence)

	other := set.Assign(NewDNSEvent(Envelope{NodeID: "other"}))
	require.NotEqual(t, replacement, other.Envelope().ProducerSessionID)
	_, _, err = set.Rotate("")
	require.Error(t, err)
}
