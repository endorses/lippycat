package voip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBufferedSIPStreamCallAwareTimeoutUsesInjectedRegistry(t *testing.T) {
	queried := ""
	factory := &sipStreamFactory{
		config: &Config{EnableCallAwareTimeout: true},
		callActive: func(callID string) bool {
			queried = callID
			return callID == "active-call"
		},
	}
	detector := NewCallIDDetector()
	detector.SetCallID("active-call")
	stream := &bufferedSIPStream{factory: factory, callIDDetector: detector}

	require.True(t, stream.isAssociatedCallActive())
	require.Equal(t, "active-call", queried)
}

func TestBufferedSIPStreamCallAwareTimeoutRequiresRegistry(t *testing.T) {
	detector := NewCallIDDetector()
	detector.SetCallID("active-call")
	stream := &bufferedSIPStream{
		factory:        &sipStreamFactory{config: &Config{EnableCallAwareTimeout: true}},
		callIDDetector: detector,
	}

	require.False(t, stream.isAssociatedCallActive())
}
