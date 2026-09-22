package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/stretchr/testify/require"
)

func TestResolvePacketBufferConfig(t *testing.T) {
	t.Run("automatic lanes follow regular capacity", func(t *testing.T) {
		resolved, err := ResolvePacketBufferConfig(PacketBufferConfig{RegularCapacity: 7})
		require.NoError(t, err)
		require.Equal(t, ResolvedPacketBufferConfig{RegularCapacity: 7, SIPCapacity: 7, OutputCapacity: 7}, resolved)
	})

	t.Run("explicit overrides", func(t *testing.T) {
		resolved, err := ResolvePacketBufferConfig(PacketBufferConfig{RegularCapacity: 7, SIPCapacity: 3, OutputCapacity: 5})
		require.NoError(t, err)
		require.Equal(t, ResolvedPacketBufferConfig{RegularCapacity: 7, SIPCapacity: 3, OutputCapacity: 5}, resolved)
	})

	for _, tc := range []struct {
		name   string
		config PacketBufferConfig
		field  string
	}{
		{name: "regular", config: PacketBufferConfig{RegularCapacity: -1}, field: "packet_buffer_size"},
		{name: "sip", config: PacketBufferConfig{RegularCapacity: 1, SIPCapacity: -1}, field: "sip_buffer_size"},
		{name: "output", config: PacketBufferConfig{RegularCapacity: 1, OutputCapacity: -1}, field: "packet_buffer_output_size"},
	} {
		t.Run(tc.name+" rejects negative", func(t *testing.T) {
			_, err := ResolvePacketBufferConfig(tc.config)
			require.ErrorContains(t, err, tc.field)
		})
	}
}

func TestConfiguredPacketBufferResolvedCapacities(t *testing.T) {
	pb, err := NewPacketBufferWithConfig(t.Context(), PacketBufferConfig{RegularCapacity: 4, SIPCapacity: 2, OutputCapacity: 3})
	require.NoError(t, err)
	t.Cleanup(pb.Close)

	snapshot := pb.Snapshot()
	require.Equal(t, 4, snapshot.RegularCapacity)
	require.Equal(t, 2, snapshot.SIPCapacity)
	require.Equal(t, 3, snapshot.OutputCapacity)
	require.LessOrEqual(t, snapshot.TotalLength(), snapshot.TotalCapacity())
}

func newDeterministicPacketBuffer(regularCap, sipCap int, gate *overflowSummaryGate) *PacketBuffer {
	return &PacketBuffer{
		ch:           make(chan PacketInfo, regularCap),
		sipCh:        make(chan PacketInfo, sipCap),
		mergedCh:     make(chan PacketInfo, 1),
		ctx:          context.Background(),
		sipFlows:     newTCPSIPFlowClassifier(),
		overflowGate: gate,
	}
}

func TestPacketBufferDeterministicPriorityAccounting(t *testing.T) {
	regular := testUDPPacketInfo("ordinary payload")
	sip := testUDPPacketInfo("INVITE sip:priority@example.invalid SIP/2.0\r\n")
	pb := newDeterministicPacketBuffer(1, 1, nil)

	require.True(t, pb.Send(sip), "SIP lane admission")
	require.True(t, pb.Send(sip), "regular fallback admission")
	require.False(t, pb.Send(sip), "both input lanes full")
	require.False(t, pb.Send(regular), "regular lane remains full")

	snapshot := pb.Snapshot()
	require.Equal(t, int64(3), snapshot.SIPClassified)
	require.Equal(t, int64(1), snapshot.SIPDemoted)
	require.Equal(t, int64(1), snapshot.SIPDropped)
	require.Equal(t, int64(1), snapshot.RegularDropped)
	require.Equal(t, int64(1), pb.GetSIPDemoted())
	require.LessOrEqual(t, snapshot.TotalLength(), snapshot.TotalCapacity())
}

func TestPacketBufferPreferentiallyDequeuesReadySIP(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	pb := newDeterministicPacketBuffer(1, 1, nil)
	pb.ctx = ctx
	pb.cancel = cancel
	pb.ch <- PacketInfo{Interface: "regular"}
	pb.sipCh <- PacketInfo{Interface: "sip"}
	pb.mergerWg.Add(1)
	go pb.mergeChannels()

	require.Equal(t, "sip", (<-pb.Receive()).Interface)
	cancel()
	pb.mergerWg.Wait()
}

func TestPacketBufferCloseCancelsSaturatedGracefulDrain(t *testing.T) {
	pb, err := NewPacketBufferWithConfig(t.Context(), PacketBufferConfig{
		RegularCapacity: 1,
		SIPCapacity:     1,
		OutputCapacity:  1,
	})
	require.NoError(t, err)
	regular := testUDPPacketInfo("ordinary payload")

	require.True(t, pb.Send(regular))
	require.Eventually(t, func() bool { return len(pb.mergedCh) == 1 }, time.Second, time.Millisecond)
	require.True(t, pb.Send(regular))
	require.Eventually(t, func() bool { return len(pb.ch) == 0 }, time.Second, time.Millisecond)

	pb.CloseInputs()
	done := make(chan struct{})
	go func() {
		pb.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel a merger blocked by a saturated output lane")
	}
}

func TestPacketBufferConcurrentLifecycleAndRecreation(t *testing.T) {
	for range 25 {
		pb, err := NewPacketBufferWithConfig(t.Context(), PacketBufferConfig{RegularCapacity: 2, SIPCapacity: 2, OutputCapacity: 2})
		require.NoError(t, err)
		var senders atomic.Int64
		done := make(chan struct{})
		go func() {
			defer close(done)
			for pb.Send(testUDPPacketInfo("ordinary payload")) {
				senders.Add(1)
			}
		}()
		go pb.CloseInputs()
		pb.Close()
		<-done
		require.True(t, pb.IsClosed())
		_ = senders.Load()
	}
}

func TestSendBlockingWaitsForSIPLaneWithoutAccountingLoss(t *testing.T) {
	sip := testUDPPacketInfo("OPTIONS sip:blocking@example.invalid SIP/2.0\r\n")
	pb := newDeterministicPacketBuffer(1, 1, nil)
	require.True(t, pb.SendBlocking(sip))

	done := make(chan bool, 1)
	go func() { done <- pb.SendBlocking(sip) }()
	select {
	case <-done:
		t.Fatal("SendBlocking returned while the SIP lane was full")
	case <-time.After(10 * time.Millisecond):
	}
	<-pb.sipCh
	select {
	case sent := <-done:
		require.True(t, sent)
	case <-time.After(time.Second):
		t.Fatal("SendBlocking did not resume after SIP capacity became available")
	}
	require.Zero(t, pb.GetSIPDemoted())
	require.Zero(t, pb.GetSIPDropped())
	require.Zero(t, pb.GetDropped())
}

func TestOverflowSummaryGateTimeAndFinalization(t *testing.T) {
	now := time.Unix(100, 0)
	var summaries []overflowSummary
	gate := newOverflowSummaryGate(time.Minute, func() time.Time { return now }, func(summary overflowSummary) {
		summaries = append(summaries, summary)
	})

	require.True(t, gate.report(PacketBufferSnapshot{RegularDropped: 1}, false))
	require.False(t, gate.report(PacketBufferSnapshot{RegularDropped: 2, SIPDemoted: 1}, false))
	now = now.Add(time.Minute)
	require.True(t, gate.report(PacketBufferSnapshot{RegularDropped: 3, SIPDemoted: 2, SIPDropped: 1}, false))
	require.Equal(t, int64(2), summaries[1].IntervalRegularDrops)
	require.Equal(t, int64(2), summaries[1].IntervalSIPDemotions)
	require.Equal(t, int64(1), summaries[1].IntervalSIPDrops)

	require.True(t, gate.report(PacketBufferSnapshot{RegularDropped: 4, SIPDemoted: 2, SIPDropped: 2}, true))
	require.True(t, summaries[2].Final)
	require.False(t, gate.report(PacketBufferSnapshot{RegularDropped: 5, SIPDemoted: 3, SIPDropped: 3}, true))
	require.Len(t, summaries, 3)
}

func TestPacketBufferCloseInputsFinalSummaryOnce(t *testing.T) {
	var emitted atomic.Int64
	pb, err := newPacketBufferWithRuntime(t.Context(), PacketBufferConfig{RegularCapacity: 1, SIPCapacity: 1, OutputCapacity: 1}, time.Hour, time.Now, func(overflowSummary) {
		emitted.Add(1)
	})
	require.NoError(t, err)

	// Seed an unreported interval directly so finalization, rather than the first
	// pressure event, is the only emitter in this lifecycle test.
	atomic.StoreInt64(&pb.dropped, 1)
	pb.CloseInputs()
	pb.CloseInputs()
	pb.Close()
	require.Equal(t, int64(1), emitted.Load())
}

func TestLogOverflowSummaryIncludesPressureAndLaneFields(t *testing.T) {
	var output bytes.Buffer
	logger.UseFile(&output)
	t.Cleanup(logger.Enable)

	logOverflowSummary(overflowSummary{
		Final:                true,
		IntervalRegularDrops: 2,
		IntervalSIPDemotions: 3,
		IntervalSIPDrops:     5,
		Snapshot: PacketBufferSnapshot{
			RegularLength: 7, RegularCapacity: 17,
			SIPLength: 11, SIPCapacity: 19,
			OutputLength: 13, OutputCapacity: 23,
			RegularDropped: 29, SIPDemoted: 31, SIPDropped: 37,
		},
	})

	var record map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record))
	require.Equal(t, "Packet buffer pressure summary", record["msg"])
	require.Equal(t, true, record["final"])
	for field, want := range map[string]float64{
		"interval_regular_dropped": 2,
		"interval_sip_demoted":     3,
		"interval_sip_dropped":     5,
		"regular_dropped":          29,
		"sip_demoted":              31,
		"sip_dropped":              37,
		"regular_len":              7,
		"regular_cap":              17,
		"sip_len":                  11,
		"sip_cap":                  19,
		"output_len":               13,
		"output_cap":               23,
	} {
		require.Equal(t, want, record[field], field)
	}
}
