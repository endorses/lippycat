package sipflow

import (
	"errors"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

type metadataObserver struct {
	validated, selected int
	err                 error
	registry            *recordingRegistry
}

func (o *metadataObserver) ObserveValidated(pipeline.SIPResult) error { o.validated++; return o.err }
func (o *metadataObserver) Selected(pipeline.SIPResult) error {
	o.selected++
	if o.registry != nil && len(o.registry.observed) == 0 {
		return errors.New("selection before authoritative observation")
	}
	return o.err
}

func TestMetadataObservationAfterValidationBeforeFiltering(t *testing.T) {
	observer := &metadataObserver{}
	flow := newStarted(t, Config{SelectionStore: newMemorySelections(), MetadataObserver: observer})
	msg := Message{Payload: sipMessage("INVITE sip:b@example.test SIP/2.0", "unmatched", "CSeq: 1 INVITE\r\n"), FilterConfigured: true}
	msg.Validate = func(sharedsip.Event) error { return errors.New("invalid") }
	require.Equal(t, pipeline.OutcomePermanentFailure, flow.Analyze(msg).Stage.Outcome)
	require.Zero(t, observer.validated)
	msg.Validate = nil
	require.Equal(t, pipeline.OutcomeFiltered, flow.Analyze(msg).Stage.Outcome)
	require.Equal(t, 1, observer.validated)
	require.Zero(t, observer.selected)
	msg.DirectMatch = true
	require.Equal(t, pipeline.OutcomeAccepted, flow.Analyze(msg).Stage.Outcome)
	require.Zero(t, observer.selected, "registry-less hunter must notify selection after tracker mutation")
}
func TestMetadataFailureDoesNotChangeOutputAndSelectionWaitsForRegistry(t *testing.T) {
	registry := &recordingRegistry{}
	observer := &metadataObserver{registry: registry, err: errors.New("admission degraded")}
	flow := newStarted(t, Config{SelectionStore: newMemorySelections(), Registry: registry})
	require.NoError(t, flow.SetMetadataObserver(observer))
	msg := Message{Payload: sipMessage("INVITE sip:b@example.test SIP/2.0", "selected", "CSeq: 1 INVITE\r\n"), FilterConfigured: true, DirectMatch: true}
	got := flow.Analyze(msg)
	require.Equal(t, pipeline.OutcomeAccepted, got.Stage.Outcome)
	require.ErrorContains(t, got.MetadataError, "admission degraded")
	require.Equal(t, 1, observer.selected)
	registry.observeError = errors.New("registry full")
	got = flow.Analyze(msg)
	require.Equal(t, pipeline.OutcomePermanentFailure, got.Stage.Outcome)
	require.Equal(t, 1, observer.selected)
}
