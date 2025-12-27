//go:build li

package li

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// benchFilterPusher is a no-op filter pusher for benchmarks.
type benchFilterPusher struct{}

func (m *benchFilterPusher) UpdateFilter(filter *management.Filter) error { return nil }
func (m *benchFilterPusher) DeleteFilter(filterID string) error           { return nil }

// setupBenchDestination creates a destination for benchmark use.
func setupBenchDestination(b *testing.B, manager *Manager) uuid.UUID {
	b.Helper()
	did := uuid.New()
	dest := &Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      9999,
		X2Enabled: true,
		X3Enabled: true,
	}
	err := manager.CreateDestination(dest)
	require.NoError(b, err)
	return did
}

// BenchmarkManager_ProcessPacket_NoMatch benchmarks packet processing when no LI tasks match.
// This measures the overhead of having LI enabled but with no active interceptions.
func BenchmarkManager_ProcessPacket_NoMatch(b *testing.B) {
	config := ManagerConfig{
		Enabled: true,
	}

	manager := NewManager(config, nil)
	err := manager.Start()
	require.NoError(b, err)
	defer manager.Stop()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID: "test-call@192.168.1.100",
			Method: "INVITE",
			From:   "alice@example.com",
			To:     "bob@example.com",
		},
	}

	// No filter IDs (no matches from upstream filter system).
	filterIDs := []string{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		manager.ProcessPacket(pkt, filterIDs)
	}
}

// BenchmarkManager_ProcessPacket_NoFilterIDs benchmarks processing with nil filter IDs.
// This is the fast path when no filters matched upstream.
func BenchmarkManager_ProcessPacket_NoFilterIDs(b *testing.B) {
	config := ManagerConfig{
		Enabled: true,
	}

	manager := NewManager(config, nil)
	err := manager.Start()
	require.NoError(b, err)
	defer manager.Stop()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID: "test-call@192.168.1.100",
			Method: "INVITE",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		manager.ProcessPacket(pkt, nil)
	}
}

// BenchmarkManager_ProcessPacket_Disabled benchmarks processing when LI is disabled.
// This should be near-zero overhead.
func BenchmarkManager_ProcessPacket_Disabled(b *testing.B) {
	config := ManagerConfig{
		Enabled: false,
	}

	manager := NewManager(config, nil)
	// Don't start - LI is disabled.

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID: "test-call@192.168.1.100",
			Method: "INVITE",
		},
	}

	filterIDs := []string{"filter-1", "filter-2"}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		manager.ProcessPacket(pkt, filterIDs)
	}
}

// BenchmarkManager_ProcessPacket_WithMatch benchmarks processing when filters match LI tasks.
func BenchmarkManager_ProcessPacket_WithMatch(b *testing.B) {
	config := ManagerConfig{
		Enabled:      true,
		FilterPusher: &benchFilterPusher{},
	}

	manager := NewManager(config, nil)
	err := manager.Start()
	require.NoError(b, err)
	defer manager.Stop()

	// Create destination first.
	destDID := setupBenchDestination(b, manager)

	// Set a packet processor callback.
	var matchCount int
	manager.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
		matchCount++
	})

	// Create a task and its filter mapping.
	xid := uuid.New()
	task := &InterceptTask{
		XID:            xid,
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX2andX3,
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "alice@example.com"},
		},
	}

	err = manager.ActivateTask(task)
	require.NoError(b, err)

	// Get the filter ID that was created.
	filterID := fmt.Sprintf("li-%s-0", xid.String())

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID: "test-call@192.168.1.100",
			Method: "INVITE",
			From:   "alice@example.com",
			To:     "bob@example.com",
		},
	}

	filterIDs := []string{filterID}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		manager.ProcessPacket(pkt, filterIDs)
	}
}

// BenchmarkManager_ProcessPacket_MultipleMatches benchmarks processing with multiple matching tasks.
func BenchmarkManager_ProcessPacket_MultipleMatches(b *testing.B) {
	matchCounts := []int{1, 5, 10}

	for _, numTasks := range matchCounts {
		b.Run(fmt.Sprintf("tasks_%d", numTasks), func(b *testing.B) {
			config := ManagerConfig{
				Enabled:      true,
				FilterPusher: &benchFilterPusher{},
			}

			manager := NewManager(config, nil)
			err := manager.Start()
			require.NoError(b, err)
			defer manager.Stop()

			// Create destination first.
			destDID := setupBenchDestination(b, manager)

			var matchCount int
			manager.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
				matchCount++
			})

			// Create multiple tasks.
			filterIDs := make([]string, numTasks)
			for i := 0; i < numTasks; i++ {
				xid := uuid.New()
				task := &InterceptTask{
					XID:            xid,
					DestinationIDs: []uuid.UUID{destDID},
					DeliveryType:   DeliveryX2andX3,
					Targets: []TargetIdentity{
						{Type: TargetTypeSIPURI, Value: fmt.Sprintf("user%d@example.com", i)},
					},
				}

				err = manager.ActivateTask(task)
				require.NoError(b, err)

				filterIDs[i] = fmt.Sprintf("li-%s-0", xid.String())
			}

			pkt := &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.200",
				SrcPort:   "5060",
				DstPort:   "5060",
				Protocol:  "SIP",
				VoIPData: &types.VoIPMetadata{
					CallID: "test-call@192.168.1.100",
					Method: "INVITE",
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				manager.ProcessPacket(pkt, filterIDs)
			}
		})
	}
}

// BenchmarkManager_ProcessPacket_HighVolume simulates high packet throughput.
func BenchmarkManager_ProcessPacket_HighVolume(b *testing.B) {
	config := ManagerConfig{
		Enabled:      true,
		FilterPusher: &benchFilterPusher{},
	}

	manager := NewManager(config, nil)
	err := manager.Start()
	require.NoError(b, err)
	defer manager.Stop()

	// Create destination first.
	destDID := setupBenchDestination(b, manager)

	var matchCount int64
	manager.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
		matchCount++
	})

	// Create 10 active tasks.
	filterIDs := make([]string, 10)
	for i := 0; i < 10; i++ {
		xid := uuid.New()
		task := &InterceptTask{
			XID:            xid,
			DestinationIDs: []uuid.UUID{destDID},
			DeliveryType:   DeliveryX2andX3,
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: fmt.Sprintf("user%d@example.com", i)},
			},
		}

		err = manager.ActivateTask(task)
		require.NoError(b, err)

		filterIDs[i] = fmt.Sprintf("li-%s-0", xid.String())
	}

	// Pre-generate packets.
	numPackets := 1000
	packets := make([]*types.PacketDisplay, numPackets)
	for i := 0; i < numPackets; i++ {
		packets[i] = &types.PacketDisplay{
			Timestamp: time.Now(),
			SrcIP:     fmt.Sprintf("192.168.%d.%d", i/256, i%256),
			DstIP:     "192.168.100.1",
			SrcPort:   "5060",
			DstPort:   "5060",
			Protocol:  "SIP",
			VoIPData: &types.VoIPMetadata{
				CallID: fmt.Sprintf("call-%d@192.168.1.100", i),
				Method: "INVITE",
			},
		}
	}

	// Use a single matching filter ID per packet.
	matchFilterIDs := []string{filterIDs[0]}

	b.ReportAllocs()
	b.ResetTimer()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		pkt := packets[i%numPackets]
		manager.ProcessPacket(pkt, matchFilterIDs)
	}
	elapsed := time.Since(start)

	pktPerSecond := float64(b.N) / elapsed.Seconds()
	b.ReportMetric(pktPerSecond, "pkt/s")
}

// BenchmarkManager_ProcessPacket_RTPStream simulates RTP stream processing.
func BenchmarkManager_ProcessPacket_RTPStream(b *testing.B) {
	config := ManagerConfig{
		Enabled:      true,
		FilterPusher: &benchFilterPusher{},
	}

	manager := NewManager(config, nil)
	err := manager.Start()
	require.NoError(b, err)
	defer manager.Stop()

	// Create destination first.
	destDID := setupBenchDestination(b, manager)

	var matchCount int64
	manager.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
		matchCount++
	})

	// Create a task for RTP interception.
	xid := uuid.New()
	task := &InterceptTask{
		XID:            xid,
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX3Only,
		Targets: []TargetIdentity{
			{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
		},
	}

	err = manager.ActivateTask(task)
	require.NoError(b, err)

	filterID := fmt.Sprintf("li-%s-0", xid.String())
	filterIDs := []string{filterID}

	// Create RTP packet.
	rtpPayload := make([]byte, 160) // G.711 20ms
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		Protocol:  "RTP",
		RawData:   rtpPayload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1000,
			Timestamp:   160000,
			PayloadType: 0,
			CallID:      "test-call@192.168.1.100",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		manager.ProcessPacket(pkt, filterIDs)
	}
	elapsed := time.Since(start)

	pktPerSecond := float64(b.N) / elapsed.Seconds()
	// G.711 20ms = 50 packets/second per call.
	concurrentCalls := pktPerSecond / 50.0

	b.ReportMetric(pktPerSecond, "pkt/s")
	b.ReportMetric(concurrentCalls, "calls@G.711")
}

// BenchmarkManager_ProcessPacket_Parallel benchmarks parallel packet processing.
func BenchmarkManager_ProcessPacket_Parallel(b *testing.B) {
	config := ManagerConfig{
		Enabled:      true,
		FilterPusher: &benchFilterPusher{},
	}

	manager := NewManager(config, nil)
	err := manager.Start()
	require.NoError(b, err)
	defer manager.Stop()

	// Create destination first.
	destDID := setupBenchDestination(b, manager)

	var matchCount int64
	manager.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
		matchCount++
	})

	// Create a task.
	xid := uuid.New()
	task := &InterceptTask{
		XID:            xid,
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX2andX3,
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "alice@example.com"},
		},
	}

	err = manager.ActivateTask(task)
	require.NoError(b, err)

	filterID := fmt.Sprintf("li-%s-0", xid.String())
	filterIDs := []string{filterID}

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID: "test-call@192.168.1.100",
			Method: "INVITE",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			manager.ProcessPacket(pkt, filterIDs)
		}
	})
}

// BenchmarkFilterManager_LookupMatches benchmarks the filter lookup operation.
func BenchmarkFilterManager_LookupMatches(b *testing.B) {
	fm := NewFilterManager(&benchFilterPusher{})

	// Simulate adding filter mappings for multiple tasks.
	numTasks := 100
	filterIDs := make([]string, numTasks)
	for i := 0; i < numTasks; i++ {
		xid := uuid.New()
		filterID := fmt.Sprintf("li-%s-0", xid.String())
		filterIDs[i] = filterID

		// Manually add to filter map (simulating ActivateTask).
		fm.mu.Lock()
		fm.filterToXID[filterID] = xid
		fm.mu.Unlock()
	}

	// Lookup with a subset of matching filter IDs.
	matchIDs := filterIDs[:5]

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = fm.LookupMatches(matchIDs)
	}
}

// BenchmarkFilterManager_LookupMatches_NoMatch benchmarks lookup with no matches.
func BenchmarkFilterManager_LookupMatches_NoMatch(b *testing.B) {
	fm := NewFilterManager(&benchFilterPusher{})

	// Simulate adding filter mappings.
	numTasks := 100
	for i := 0; i < numTasks; i++ {
		xid := uuid.New()
		filterID := fmt.Sprintf("li-%s-0", xid.String())

		fm.mu.Lock()
		fm.filterToXID[filterID] = xid
		fm.mu.Unlock()
	}

	// Lookup with non-matching filter IDs.
	noMatchIDs := []string{"non-li-filter-1", "non-li-filter-2", "other-filter"}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = fm.LookupMatches(noMatchIDs)
	}
}

// BenchmarkRegistry_GetTaskDetails benchmarks task lookup by XID.
func BenchmarkRegistry_GetTaskDetails(b *testing.B) {
	registry := NewRegistry(nil)
	registry.Start()
	defer registry.Stop()

	// Create a destination for task validation.
	destDID := uuid.New()
	err := registry.CreateDestination(&Destination{
		DID:       destDID,
		Address:   "127.0.0.1",
		Port:      9999,
		X2Enabled: true,
	})
	require.NoError(b, err)

	// Create tasks.
	numTasks := 100
	xids := make([]uuid.UUID, numTasks)
	for i := 0; i < numTasks; i++ {
		xid := uuid.New()
		xids[i] = xid

		task := &InterceptTask{
			XID:            xid,
			DestinationIDs: []uuid.UUID{destDID},
			DeliveryType:   DeliveryX2andX3,
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: fmt.Sprintf("user%d@example.com", i)},
			},
		}

		err := registry.ActivateTask(task)
		require.NoError(b, err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		xid := xids[i%numTasks]
		_, _ = registry.GetTaskDetails(xid)
	}
}

// BenchmarkRegistry_GetTaskDetails_Parallel benchmarks parallel task lookups.
func BenchmarkRegistry_GetTaskDetails_Parallel(b *testing.B) {
	registry := NewRegistry(nil)
	registry.Start()
	defer registry.Stop()

	// Create a destination for task validation.
	destDID := uuid.New()
	err := registry.CreateDestination(&Destination{
		DID:       destDID,
		Address:   "127.0.0.1",
		Port:      9999,
		X2Enabled: true,
	})
	require.NoError(b, err)

	numTasks := 100
	xids := make([]uuid.UUID, numTasks)
	for i := 0; i < numTasks; i++ {
		xid := uuid.New()
		xids[i] = xid

		task := &InterceptTask{
			XID:            xid,
			DestinationIDs: []uuid.UUID{destDID},
			DeliveryType:   DeliveryX2andX3,
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: fmt.Sprintf("user%d@example.com", i)},
			},
		}

		err := registry.ActivateTask(task)
		require.NoError(b, err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			xid := xids[i%numTasks]
			_, _ = registry.GetTaskDetails(xid)
			i++
		}
	})
}
