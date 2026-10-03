package eventanalysis

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
)

func TestNetworkMessageParityWithoutLogSink(t *testing.T) {
	packets, err := eventfixture.NetworkMessages()
	require.NoError(t, err)
	var paths [][]events.Event
	for _, transported := range []bool{false, true} {
		r, d, sink := testRuntime(t, 64)
		r.cfg.AnalysisEpoch = "parity-fixture-epoch"
		source := Source{NodeID: "node", CaptureSource: "fixture", CaptureEpoch: "epoch"}
		for _, info := range packets {
			if transported {
				ci := info.Packet.Metadata().CaptureInfo
				meta := protocolmeta.Enrich(info.Packet, nil, false)
				// A cached label alone must neither supply fields nor suppress parsing.
				meta.Protocol = "UDP"
				require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{{Data: info.Packet.Data(), TimestampNs: ci.Timestamp.UnixNano(), LinkType: uint32(info.LinkType), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), InterfaceName: info.Interface, Metadata: meta}}))
			} else {
				require.NoError(t, r.ObservePacket(source, info))
			}
		}
		r.EOF()
		require.Zero(t, r.Stats().DHCP.Entries)
		require.Zero(t, r.Stats().NTP.Entries)
		r.Close()
		require.NoError(t, d.Close(context.Background()))
		var observations []events.Event
		for _, event := range sink.events {
			if event.Kind() == events.KindDHCP || event.Kind() == events.KindNTP {
				observations = append(observations, event)
			}
		}
		require.Len(t, observations, 5)
		require.Equal(t, events.AssociationRequest, observations[0].(events.DHCPEvent).Association)
		require.Equal(t, events.AssociationUnique, observations[1].(events.DHCPEvent).Association)
		require.Equal(t, events.AssociationRequest, observations[3].(events.NTPEvent).Association)
		require.Equal(t, events.AssociationUnique, observations[4].(events.NTPEvent).Association)
		require.NotEqual(t, observations[0].Envelope().EventID, observations[2].Envelope().EventID)
		require.NotEqual(t, observations[0].Envelope().UID, observations[1].Envelope().UID)
		paths = append(paths, observations)
	}
	for i := range paths[0] {
		// Flow UIDs are runtime-local; protocol data and association IDs are stable.
		switch a := paths[0][i].(type) {
		case events.DHCPEvent:
			b := paths[1][i].(events.DHCPEvent)
			a.EventEnvelope = events.Envelope{}
			b.EventEnvelope = events.Envelope{}
			require.Equal(t, a, b)
		case events.NTPEvent:
			b := paths[1][i].(events.NTPEvent)
			a.EventEnvelope = events.Envelope{}
			b.EventEnvelope = events.Envelope{}
			require.Equal(t, a, b)
		}
	}
}

func TestNetworkAssociationScopeAndLifecycle(t *testing.T) {
	packets, err := eventfixture.NetworkMessages()
	require.NoError(t, err)
	for _, boundary := range []string{"source", "epoch", "reset", "eof", "expiry"} {
		t.Run(boundary, func(t *testing.T) {
			r, d, sink := testRuntime(t, 64)
			source := Source{NodeID: "node", CaptureSource: "fixture", CaptureEpoch: "one"}
			require.NoError(t, r.ObservePacket(source, packets[3]))
			switch boundary {
			case "source":
				source.CaptureSource = "other"
			case "epoch":
				source.CaptureEpoch = "two"
			case "reset":
				require.NoError(t, r.Reset())
			case "eof":
				r.EOF()
			case "expiry":
				r.Expire(packets[3].Packet.Metadata().Timestamp.Add(time.Minute))
			}
			require.NoError(t, r.ObservePacket(source, packets[4]))
			r.Close()
			require.NoError(t, d.Close(context.Background()))
			var replies []events.NTPEvent
			for _, event := range sink.events {
				if ev, ok := event.(events.NTPEvent); ok && ev.Mode == 4 {
					replies = append(replies, ev)
				}
			}
			require.Len(t, replies, 1)
			require.NotEqual(t, events.AssociationUnique, replies[0].Association)
			require.Empty(t, replies[0].AssociationID)
		})
	}
}

func TestNetworkMalformedInputIsPartialOrRejected(t *testing.T) {
	packets, err := eventfixture.NetworkMessages()
	require.NoError(t, err)
	r, d, sink := testRuntime(t, 32)
	source := Source{NodeID: "node", CaptureSource: "fixture"}
	ntpPayload := append([]byte(nil), packets[3].Packet.TransportLayer().LayerPayload()...)
	ntpPayload = append(ntpPayload, 1, 2, 3) // short extension, valid time header
	malformed, err := eventfixture.NetworkDatagram("192.0.2.20", "192.0.2.123", 40000, 123, ntpPayload, eventfixture.BaseTime)
	require.NoError(t, err)
	require.NoError(t, r.ObservePacket(source, malformed))
	ntpPayload[0] = 0x26 // control mode is excluded completely
	control, err := eventfixture.NetworkDatagram("192.0.2.20", "192.0.2.123", 40000, 123, ntpPayload, eventfixture.BaseTime)
	require.NoError(t, err)
	require.NoError(t, r.ObservePacket(source, control))
	dhcpPayload := append([]byte(nil), packets[0].Packet.TransportLayer().LayerPayload()...)
	dhcpPayload = append(dhcpPayload[:len(dhcpPayload)-1], 12, 10, 'a') // truncated option after type
	malformed, err = eventfixture.NetworkDatagram("0.0.0.0", "255.255.255.255", 68, 67, dhcpPayload, eventfixture.BaseTime)
	require.NoError(t, err)
	require.NoError(t, r.ObservePacket(source, malformed))
	r.Close()
	require.NoError(t, d.Close(context.Background()))
	var observations []events.Event
	for _, event := range sink.events {
		switch ev := event.(type) {
		case events.DHCPEvent:
			require.True(t, ev.Truncated)
			require.Equal(t, events.AssociationNotApplicable, ev.Association)
			observations = append(observations, event)
		case events.NTPEvent:
			require.True(t, ev.Truncated)
			require.Equal(t, events.AssociationMissing, ev.Association)
			observations = append(observations, event)
		}
	}
	require.Len(t, observations, 2)
	for _, event := range observations {
		require.True(t, event.Envelope().Partial)
	}
}
