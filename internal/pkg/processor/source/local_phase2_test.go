package source

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func phase2Filter(full, media func(gopacket.Packet) (bool, []string)) *recordingApplicationFilter {
	return &recordingApplicationFilter{match: full, packetLevelMatch: media}
}

func phase2SIPMatcher(packet gopacket.Packet) (bool, []string) {
	if bytes.HasPrefix(phase0PacketPayload(packet), []byte("INVITE ")) {
		return true, []string{"direct-sip"}
	}
	return false, nil
}

func TestLocalSourcePhase2_ClassifiedMediaUsesPacketLevelMatcher(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet func(*testing.T) capture.PacketInfo
	}{
		{name: "RTP", packet: phase0RTPPacket},
		{name: "RTCP", packet: phase0RTCPPacket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processorFilter := phase2Filter(phase2SIPMatcher, nil)
			filter := phase2Filter(nil, func(gopacket.Packet) (bool, []string) {
				return false, nil
			})
			packets := runPhase0LocalSourceWithProcessorFilter(t, filter, processorFilter,
				phase0SIPPacket(t, "INVITE", true), tc.packet(t))
			require.Len(t, packets, 2)
			require.NotNil(t, packets[1].Metadata.GetRtp())
			full, media := filter.counts()
			require.Zero(t, full, "the processor's SIP verdict must be reused by LocalSource")
			require.Equal(t, 1, media, "classified media must use exactly one packet-level match")
		})
	}
}

func TestLocalSourcePhase2_RTPIdentityOnlySelection(t *testing.T) {
	t.Run("inherits selected call without a media payload full match", func(t *testing.T) {
		processorFilter := phase2Filter(phase2SIPMatcher, nil)
		filter := phase2Filter(nil, func(gopacket.Packet) (bool, []string) { return false, nil })
		packets := runPhase0LocalSourceWithProcessorFilter(t, filter, processorFilter,
			phase0SIPPacket(t, "INVITE", true), phase0RTPPacket(t))
		require.Len(t, packets, 2)
		require.Equal(t, []string{"direct-sip"}, packets[1].MatchedFilterIds)
		full, media := filter.counts()
		require.Zero(t, full)
		require.Equal(t, 1, media)
	})

	t.Run("drops without inherited selection", func(t *testing.T) {
		filter := phase2Filter(func(gopacket.Packet) (bool, []string) { return true, nil },
			func(gopacket.Packet) (bool, []string) { return false, nil })
		packets := runPhase0LocalSource(t, filter, phase0SIPPacket(t, "INVITE", true), phase0RTPPacket(t))
		require.Len(t, packets, 1, "the SDP-bearing SIP packet establishes association but no cached identity")
		require.NotNil(t, packets[0].Metadata.GetSip())
		full, media := filter.counts()
		require.Equal(t, 1, full)
		require.Equal(t, 1, media)
	})
}

func TestLocalSourcePhase2_RTPDirectAndInheritedIDComposition(t *testing.T) {
	t.Run("direct media match needs no selected call", func(t *testing.T) {
		filter := phase2Filter(func(gopacket.Packet) (bool, []string) {
			// Establish RTP association without caching a selected-call ID.
			return true, nil
		}, func(gopacket.Packet) (bool, []string) {
			return true, []string{"direct-ip"}
		})
		packets := runPhase0LocalSource(t, filter, phase0SIPPacket(t, "INVITE", true), phase0RTPPacket(t))
		require.Len(t, packets, 2)
		require.Equal(t, []string{"direct-ip"}, packets[1].MatchedFilterIds)
		full, media := filter.counts()
		require.Equal(t, 1, full)
		require.Equal(t, 1, media)
	})

	t.Run("direct IDs precede inherited IDs and duplicates are removed", func(t *testing.T) {
		filter := phase2Filter(func(packet gopacket.Packet) (bool, []string) {
			if bytes.HasPrefix(phase0PacketPayload(packet), []byte("INVITE ")) {
				return true, []string{"shared", "inherited"}
			}
			return false, nil
		}, func(gopacket.Packet) (bool, []string) {
			return true, []string{"direct-ip", "shared", "", "direct-ip"}
		})
		packets := runPhase0LocalSourceWithProcessorFilter(t, filter, filter,
			phase0SIPPacket(t, "INVITE", true), phase0RTPPacket(t))
		require.Len(t, packets, 2)
		require.Equal(t, []string{"direct-ip", "shared", "inherited"}, packets[1].MatchedFilterIds)
	})
}

func TestLocalSourcePhase2_AmbiguousSharedEndpointFailsClosed(t *testing.T) {
	const (
		callA = "synthetic-shared-leg-a@example.invalid"
		callB = "synthetic-shared-leg-b@example.invalid"
	)

	sharedInvite := func(t *testing.T, callID string) capture.PacketInfo {
		t.Helper()
		return phase0UDPPacket(t, phase0MediaIP, "192.0.2.20", 5060, 5060,
			phase0SIPPayload("INVITE", callID, true))
	}
	identityMatcher := func(packet gopacket.Packet) (bool, []string) {
		payload := phase0PacketPayload(packet)
		switch {
		case bytes.Contains(payload, []byte("Call-ID: "+callA)):
			return true, []string{"identity-a"}
		case bytes.Contains(payload, []byte("Call-ID: "+callB)):
			return true, []string{"identity-b"}
		default:
			return false, nil
		}
	}

	t.Run("direct IP match survives without foreign identity union", func(t *testing.T) {
		filter := phase2Filter(identityMatcher, func(gopacket.Packet) (bool, []string) {
			return true, []string{"direct-ip"}
		})
		packets := runPhase0LocalSourceWithProcessorFilter(t, filter, filter,
			sharedInvite(t, callA), sharedInvite(t, callB), phase0RTPPacket(t))

		require.Len(t, packets, 3)
		media := packets[2]
		require.NotNil(t, media.Metadata.GetRtp(), "fixture must remain classified as RTP")
		require.Nil(t, media.Metadata.GetSip(), "ambiguous media must not carry a guessed Call-ID")
		require.Equal(t, []string{"direct-ip"}, media.MatchedFilterIds,
			"direct packet attribution remains valid, but neither call's identity may be inherited")
		require.Equal(t, []string{"direct-ip"}, media.DirectMatchedFilterIds)
		require.Empty(t, media.InheritedMatchedFilterIds,
			"ambiguous media must expose no identity provenance at the LI boundary")
	})

	t.Run("identity-only media is not selected", func(t *testing.T) {
		filter := phase2Filter(identityMatcher, func(gopacket.Packet) (bool, []string) {
			return false, nil
		})
		packets := runPhase0LocalSourceWithProcessorFilter(t, filter, filter,
			sharedInvite(t, callA), sharedInvite(t, callB), phase0RTPPacket(t))

		require.Len(t, packets, 2, "ambiguous RTP must not enter either identity-selected task")
		for _, packet := range packets {
			require.NotNil(t, packet.Metadata.GetSip())
		}
	})
}

func TestLocalSourcePhase2_CachedFilterLookupIsSingleCallAndDeduplicated(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())
	now := time.Now()
	s.callFilterCache.Store("leg-a", cachedFilterIDs{filterIDs: []string{"a", "shared", ""}, storedAt: now})
	s.callFilterCache.Store("unrelated", cachedFilterIDs{filterIDs: []string{"forbidden"}, storedAt: now})
	s.callFilterCache.Store("leg-b", cachedFilterIDs{filterIDs: []string{"shared", "b", "b"}, storedAt: now})

	require.Equal(t, []string{"a", "shared"}, s.cachedFilterIDsForCall("leg-a"))
	require.Equal(t, []string{"shared", "b"}, s.cachedFilterIDsForCall("leg-b"))
	require.Empty(t, s.cachedFilterIDsForCall(""))
}

func runPhase2Injected(t *testing.T, s *LocalSource, injected InjectedPacket) (*data.CapturedPacket, bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.ctx = ctx
	s.config.BatchSize = 1
	injection := make(chan InjectedPacket, 1)
	s.SetTCPInjectionChannel(injection)
	input := make(chan capture.PacketInfo)
	done := make(chan struct{})
	go func() {
		s.batchingWorker(input)
		close(done)
	}()
	injection <- injected
	select {
	case batch := <-s.Batches():
		require.Len(t, batch.Envelopes, 1)
		packet, err := grpcadapter.ToCapturedPacket(batch.Envelopes[0])
		require.NoError(t, err)
		batch.RunAfterProcess()
		cancel()
		<-done
		return packet, true
	case <-time.After(25 * time.Millisecond):
		cancel()
		<-done
		return nil, false
	}
}

func TestLocalSourcePhase2_ReassembledSIPCompositionAndCompletion(t *testing.T) {
	t.Run("forward composes direct then inherited and completes once", func(t *testing.T) {
		s := NewLocalSource(DefaultLocalSourceConfig())
		s.SetApplicationFilter(phase2Filter(func(gopacket.Packet) (bool, []string) {
			return true, []string{"direct", "shared", "direct"}
		}, nil))
		s.callFilterCache.Store("tcp-call", cachedFilterIDs{filterIDs: []string{"shared", "inherited"}, storedAt: time.Now()})
		var completions atomic.Int32
		packet, forwarded := runPhase2Injected(t, s, InjectedPacket{
			PacketInfo:   buildTCPPacket(t, 1),
			Metadata:     &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "tcp-call"}},
			AfterProcess: func() { completions.Add(1) },
		})
		require.True(t, forwarded)
		require.Equal(t, []string{"direct", "shared", "inherited"}, packet.MatchedFilterIds)
		cached, ok := s.callFilterCache.Load("tcp-call")
		require.True(t, ok)
		require.Equal(t, []string{"direct", "shared"}, cached.filterIDs,
			"only stable direct IDs may be written back to the call cache")
		require.Equal(t, int32(1), completions.Load())
	})

	t.Run("drop completes once", func(t *testing.T) {
		s := NewLocalSource(DefaultLocalSourceConfig())
		s.SetApplicationFilter(phase2Filter(func(gopacket.Packet) (bool, []string) { return false, nil }, nil))
		var completions atomic.Int32
		_, forwarded := runPhase2Injected(t, s, InjectedPacket{
			PacketInfo:   buildTCPPacket(t, 1),
			Metadata:     &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "unselected"}},
			AfterProcess: func() { completions.Add(1) },
		})
		require.False(t, forwarded)
		require.Equal(t, int32(1), completions.Load())
	})

	t.Run("normalization error completes once", func(t *testing.T) {
		s := NewLocalSource(DefaultLocalSourceConfig())
		var completions atomic.Int32
		_, forwarded := runPhase2Injected(t, s, InjectedPacket{
			PacketInfo: capture.PacketInfo{},
			// Invalid UTF-8 makes protobuf metadata encoding fail in normalization.
			Metadata:     &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: string([]byte{0xff})}},
			AfterProcess: func() { completions.Add(1) },
		})
		require.False(t, forwarded)
		require.Equal(t, int32(1), completions.Load())
	})
}

func TestLocalSourcePhase2_CredibleSIPStartLineBoundary(t *testing.T) {
	credible := [][]byte{
		[]byte("INVITE sip:service@example.invalid SIP/2.0\r\n"),
		[]byte("SIP/2.0 200 OK\r\n"),
		[]byte("OPTIONS sip:service@example.invalid SIP/2.0\n"),
	}
	for _, payload := range credible {
		packet := phase0UDPPacket(t, "198.51.100.10", "198.51.100.20", 5060, 5060, payload)
		require.True(t, hasCredibleSIPStartLine(packet.Packet), string(payload))
	}

	notCredible := [][]byte{
		phase0UnclassifiedPayload(),
		phase0RTPPayload(),
		[]byte("INVITE-not-really-sip"),
		[]byte("INVITEX sip:x@example.invalid SIP/2.0\r\n"),
		[]byte("INVITE sip:x@example.invalid extra SIP/2.0\r\n"),
		[]byte("SIP/2.0-not-a-response"),
		[]byte("SIP/2.0 200OK\r\n"),
		[]byte("SIP/2.0 999 Invalid\r\n"),
		[]byte("SIP/2.0 000 Invalid\r\n"),
		[]byte("binary\nINVITE sip:x@example.invalid SIP/2.0\r\n"),
		append(bytes.Repeat([]byte{'X'}, 512), []byte(" INVITE sip:x@example.invalid SIP/2.0")...),
	}
	for _, payload := range notCredible {
		packet := phase0UDPPacket(t, "198.51.100.10", "198.51.100.20", 5060, 5060, payload)
		require.False(t, hasCredibleSIPStartLine(packet.Packet), "%x", payload)
	}

	packet := phase0UDPPacket(t, "198.51.100.10", "198.51.100.20", 5060, 5060, credible[0])
	require.Zero(t, testing.AllocsPerRun(1000, func() {
		hasCredibleSIPStartLine(packet.Packet)
	}), "credible SIP classification must remain allocation-free")
}

// Compile-time guard that the synthetic packet helper continues to produce
// UDP packets for the classification tests above.
func TestLocalSourcePhase2_FixturesAreUDP(t *testing.T) {
	require.IsType(t, &layers.UDP{}, phase0RTPPacket(t).Packet.TransportLayer())
}
