package grpcadapter

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func TestLocalCaptureCapabilitiesNeverCrossTransport(t *testing.T) {
	input := &pipeline.PacketEnvelope{Data: []byte{1}, Source: pipeline.SourceProvenance{CapturePolicyGeneration: 99}, CurrentCaptureSelection: func() bool { return true }}
	wire, err := ToCapturedPacket(input)
	require.NoError(t, err)
	output, err := FromCapturedPacket(wire, pipeline.SourceProvenance{})
	require.NoError(t, err)
	require.Zero(t, output.Source.CapturePolicyGeneration)
	require.Nil(t, output.CurrentCaptureSelection)
}
