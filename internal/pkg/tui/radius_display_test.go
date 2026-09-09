//go:build tui || all

package tui

import (
	"bytes"
	"encoding/json"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
)

func radiusDisplayFixture(t *testing.T, record int) *radius.Observation {
	t.Helper()
	f, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	var raw []byte
	var ci gopacket.CaptureInfo
	for i := 0; i < record; i++ {
		raw, ci, err = r.ReadPacketData()
		require.NoError(t, err)
	}
	scope := radius.CaptureScope{OriginNodeID: "origin", SourceID: "mirror", Epoch: [16]byte{1}}
	o, _, err := radius.DecodePacket(raw, r.LinkType(), ci, scope, radius.Identity{Epoch: scope.Epoch, Sequence: uint64(record)})
	require.NoError(t, err)
	if record == 1 {
		// Convert NAS-Identifier into a credential-bearing AVP without changing lengths,
		// and retain a binary User-Name to exercise safe hex presentation.
		start := bytes.Index(raw, o.Message.Raw)
		require.GreaterOrEqual(t, start, 0)
		offset := start + 20
		for _, a := range o.Message.Attributes {
			if a.Type == 32 {
				raw[offset] = 2
			}
			if a.Type == 1 {
				raw[offset+2] = 0x1b
			}
			offset += len(a.Raw)
		}
		o, _, err = radius.DecodePacket(raw, r.LinkType(), ci, scope, o.Capture.ID)
		require.NoError(t, err)
		o.Association = radius.Association{Status: radius.AssociationRequest, RequestInstanceID: o.Capture.ID, RequestObservationID: o.Capture.ID, RequestFirstSeen: ci.Timestamp}
	} else {
		o.Association = radius.Association{Status: radius.AssociationUnique, RequestInstanceID: radius.Identity{Epoch: scope.Epoch, Sequence: 1}, RequestObservationID: radius.Identity{Epoch: scope.Epoch, Sequence: 1}, RequestFirstSeen: ci.Timestamp.Add(-time.Second)}
	}
	return o
}

func TestRADIUSTUIDisplaySafeFixtureProjection(t *testing.T) {
	for _, record := range []int{1, 2} {
		o := radiusDisplayFixture(t, record)
		env := &pipeline.PacketEnvelope{Data: o.Packet, LinkType: o.Capture.LinkType, CaptureTime: o.Capture.Timestamp, CaptureLength: o.Capture.CapturedLength, OriginalLength: o.Capture.OriginalLength, RADIUS: o}
		for _, fast := range []bool{false, true} {
			var display components.PacketDisplay
			if fast {
				display = convertEnvelopeFast(env)
			} else {
				display = convertEnvelope(env, nil)
			}
			require.NotNil(t, display.RADIUSData)
			require.Equal(t, "RADIUS", display.Protocol)
			require.Equal(t, string(o.Association.Status), display.RADIUSData.Association)
			require.Equal(t, radius.IdentityString(o.Association.RequestInstanceID), display.RADIUSData.RequestID)
			if fast {
				require.Nil(t, display.RawData)
			} else {
				require.Equal(t, o.Packet, display.RawData)
			}
			require.Equal(t, o.Capture.LinkType, display.LinkType)
			require.True(t, o.Capture.Timestamp.Equal(display.Timestamp))
			encoded, err := json.Marshal(display.RADIUSData)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), "6e61732d61")
			require.NotContains(t, string(encoded), "authenticator")
			require.NotContains(t, display.Info, "\x1b")
			if record == 1 {
				require.Contains(t, string(encoded), "1:hex:1b")
			} else {
				require.Empty(t, display.RADIUSData.Attributes)
			}
		}
	}
}
