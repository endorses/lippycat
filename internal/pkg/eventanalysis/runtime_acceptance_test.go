package eventanalysis

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/require"
)

func TestObserveCapturedAcceptedReportsPartialOwnership(t *testing.T) {
	runtime, dispatcher, _ := testRuntime(t, 16)
	accepted, err := runtime.ObserveCapturedAccepted(Source{NodeID: "node"}, []*data.CapturedPacket{nil, packet(time.Unix(10, 0))})
	require.ErrorContains(t, err, "1 of 2 invalid")
	require.Equal(t, []bool{false, true}, accepted)
	runtime.Close()
	accepted, err = runtime.ObserveCapturedAccepted(Source{NodeID: "node"}, []*data.CapturedPacket{packet(time.Unix(11, 0))})
	require.ErrorContains(t, err, "closed")
	require.Empty(t, accepted)
	require.NoError(t, dispatcher.Close(context.Background()))
}
