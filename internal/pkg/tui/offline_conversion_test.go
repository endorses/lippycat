//go:build tui || all

package tui

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestOfflineConversionBorrowsBytesWhileLiveConversionOwnsThem(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xb5, 1, 2, 3, 4}
	pkt := gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.NoCopy)
	env := pipeline.NewDecodedPacketEnvelope(pkt, layers.LinkTypeEthernet)
	protocols := detector.NewWithDefaultSignatures()
	defer protocols.Shutdown()
	owned := convertEnvelopeWithState(env, nil, protocols, newOfflineSIPFlows())
	borrowed := convertEnvelopeWithRawOwnership(env, nil, protocols, newOfflineSIPFlows(), false)
	require.Equal(t, owned, borrowed)
	raw[len(raw)-1] = 99
	require.Equal(t, byte(4), owned.RawData[len(raw)-1])
	require.Equal(t, byte(99), borrowed.RawData[len(raw)-1])
}
