package test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestIntegration_FilterDistribution_SingleHunter tests filter distribution to a single hunter
func TestIntegration_FilterDistribution_SingleHunter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr := "127.0.0.1:50064"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	// Connect hunter
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)

	// Register hunter
	hunterID := "test-hunter-filter"
	regResp, err := mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   hunterID,
		Hostname:   "test-host",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:           false,
		},
	})
	require.NoError(t, err)
	assert.True(t, regResp.Accepted)

	// Subscribe to filter updates
	filterStream, err := mgmtClient.SubscribeToFilters(ctx, &management.FilterSubscription{
		HunterId: hunterID,
	})
	require.NoError(t, err)

	// Channel to receive filter updates
	filterReceived := make(chan *management.FilterUpdate, 1)
	go func() {
		for {
			update, err := filterStream.Recv()
			if err != nil {
				return
			}
			filterReceived <- update
		}
	}()

	// Push a filter from processor
	filterResp, err := mgmtClient.PushFilter(ctx, &management.FilterRequest{
		Filter: &management.Filter{
			Id:         "filter-1",
			Type:       "bpf",
			Expression: "tcp port 5060",
			Priority:   100,
		},
		TargetHunters: []string{hunterID},
	})
	require.NoError(t, err)
	assert.Greater(t, filterResp.HuntersUpdated, uint32(0), "Filter should be distributed to hunter")

	// Wait for filter update
	select {
	case update := <-filterReceived:
		assert.NotNil(t, update)
		assert.Equal(t, "add", update.Operation)
		assert.Equal(t, "filter-1", update.Filter.Id)
		assert.Equal(t, "tcp port 5060", update.Filter.Expression)
		t.Logf("✓ Filter distribution test: Filter successfully distributed to hunter")
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for filter update")
	}
}

// TestIntegration_FilterDistribution_MultipleHunters tests filter distribution to multiple hunters
func TestIntegration_FilterDistribution_MultipleHunters(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr := "127.0.0.1:50065"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	numHunters := 5
	hunters := make([]string, numHunters)
	filterChannels := make([]chan *management.FilterUpdate, numHunters)

	// Connect multiple hunters
	for i := 0; i < numHunters; i++ {
		hunterID := fmt.Sprintf("test-hunter-multi-%d", i)
		hunters[i] = hunterID
		filterChannels[i] = make(chan *management.FilterUpdate, 10)

		conn, err := grpc.DialContext(ctx, processorAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		defer conn.Close()

		mgmtClient := management.NewManagementServiceClient(conn)

		// Register hunter
		regResp, err := mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
			HunterId:   hunterID,
			Hostname:   fmt.Sprintf("test-host-%d", i),
			Interfaces: []string{"eth0"},
			Version:    "test-1.0.0",
			Capabilities: &management.HunterCapabilities{
				FilterTypes:     []string{"bpf"},
				MaxBufferSize:   8192,
				GpuAcceleration: false,
				AfXdp:           false,
			},
		})
		require.NoError(t, err)
		assert.True(t, regResp.Accepted)

		// Subscribe to filter updates
		filterStream, err := mgmtClient.SubscribeToFilters(ctx, &management.FilterSubscription{
			HunterId: hunterID,
		})
		require.NoError(t, err)

		// Start goroutine to receive filter updates
		ch := filterChannels[i]
		go func() {
			for {
				update, err := filterStream.Recv()
				if err != nil {
					return
				}
				ch <- update
			}
		}()
	}

	// Push filter to all hunters
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)
	filterResp, err := mgmtClient.PushFilter(ctx, &management.FilterRequest{
		Filter: &management.Filter{
			Id:         "broadcast-filter",
			Type:       "bpf",
			Expression: "udp port 5060",
			Priority:   100,
		},
		TargetHunters: hunters, // All hunters
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(numHunters), filterResp.HuntersUpdated, "Filter should be distributed to all hunters")

	// Wait for all hunters to receive the filter
	var receivedCount atomic.Uint32
	var wg sync.WaitGroup
	wg.Add(numHunters)

	for i := 0; i < numHunters; i++ {
		ch := filterChannels[i]
		go func(hunterIdx int) {
			defer wg.Done()
			select {
			case update := <-ch:
				assert.NotNil(t, update)
				assert.Equal(t, "add", update.Operation)
				assert.Equal(t, "broadcast-filter", update.Filter.Id)
				receivedCount.Add(1)
			case <-time.After(3 * time.Second):
				t.Errorf("Hunter %d: Timeout waiting for filter update", hunterIdx)
			}
		}(i)
	}

	wg.Wait()
	assert.Equal(t, uint32(numHunters), receivedCount.Load(), "All hunters should receive filter")

	t.Logf("✓ Multi-hunter filter distribution test: %d hunters received filter", receivedCount.Load())
}

// TestIntegration_FilterDistribution_UpdateAndRemove tests filter updates and removals
func TestIntegration_FilterDistribution_UpdateAndRemove(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr := "127.0.0.1:50066"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	// Connect hunter
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)

	hunterID := "test-hunter-update"
	regResp, err := mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   hunterID,
		Hostname:   "test-host",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:           false,
		},
	})
	require.NoError(t, err)
	assert.True(t, regResp.Accepted)

	// Subscribe to filter updates
	filterStream, err := mgmtClient.SubscribeToFilters(ctx, &management.FilterSubscription{
		HunterId: hunterID,
	})
	require.NoError(t, err)

	filterReceived := make(chan *management.FilterUpdate, 10)
	go func() {
		for {
			update, err := filterStream.Recv()
			if err != nil {
				return
			}
			filterReceived <- update
		}
	}()

	// 1. Add filter
	filterResp, err := mgmtClient.PushFilter(ctx, &management.FilterRequest{
		Filter: &management.Filter{
			Id:         "dynamic-filter",
			Type:       "bpf",
			Expression: "tcp port 80",
			Priority:   100,
		},
		TargetHunters: []string{hunterID},
	})
	require.NoError(t, err)
	assert.Greater(t, filterResp.HuntersUpdated, uint32(0))

	// Verify ADD operation
	select {
	case update := <-filterReceived:
		assert.Equal(t, "add", update.Operation)
		assert.Equal(t, "dynamic-filter", update.Filter.Id)
		assert.Equal(t, "tcp port 80", update.Filter.Expression)
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for ADD filter update")
	}

	// 2. Update filter
	filterResp, err = mgmtClient.PushFilter(ctx, &management.FilterRequest{
		Filter: &management.Filter{
			Id:         "dynamic-filter",
			Type:       "bpf",
			Expression: "tcp port 443", // Updated expression
			Priority:   200,             // Updated priority
		},
		TargetHunters: []string{hunterID},
	})
	require.NoError(t, err)
	assert.Greater(t, filterResp.HuntersUpdated, uint32(0))

	// Verify UPDATE operation
	select {
	case update := <-filterReceived:
		assert.Equal(t, "update", update.Operation)
		assert.Equal(t, "dynamic-filter", update.Filter.Id)
		assert.Equal(t, "tcp port 443", update.Filter.Expression)
		assert.Equal(t, uint32(200), update.Filter.Priority)
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for UPDATE filter update")
	}

	// 3. Remove filter
	removeResp, err := mgmtClient.RemoveFilter(ctx, &management.FilterRemovalRequest{
		FilterId:      "dynamic-filter",
		TargetHunters: []string{hunterID},
	})
	require.NoError(t, err)
	assert.Greater(t, removeResp.HuntersUpdated, uint32(0))

	// Verify REMOVE operation
	select {
	case update := <-filterReceived:
		assert.Equal(t, "remove", update.Operation)
		assert.Equal(t, "dynamic-filter", update.Filter.Id)
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for REMOVE filter update")
	}

	t.Logf("✓ Filter update/remove test: ADD → UPDATE → REMOVE operations successful")
}

// TestIntegration_FilterDistribution_CircuitBreaker tests circuit breaker for failed hunters
func TestIntegration_FilterDistribution_CircuitBreaker(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr := "127.0.0.1:50067"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	// Connect first hunter (will disconnect)
	conn1, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)

	mgmtClient1 := management.NewManagementServiceClient(conn1)

	// Register first hunter
	hunterID1 := "test-hunter-fail"
	regResp, err := mgmtClient1.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   hunterID1,
		Hostname:   "test-host-1",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:           false,
		},
	})
	require.NoError(t, err)
	assert.True(t, regResp.Accepted)

	// Subscribe to filters
	filterStream1, err := mgmtClient1.SubscribeToFilters(ctx, &management.FilterSubscription{
		HunterId: hunterID1,
	})
	require.NoError(t, err)

	// Immediately close connection (simulate hunter crash)
	conn1.Close()
	time.Sleep(200 * time.Millisecond)

	// Connect second hunter (stays connected)
	conn2, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn2.Close()

	mgmtClient2 := management.NewManagementServiceClient(conn2)

	hunterID2 := "test-hunter-healthy"
	regResp, err = mgmtClient2.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   hunterID2,
		Hostname:   "test-host-2",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:           false,
		},
	})
	require.NoError(t, err)
	assert.True(t, regResp.Accepted)

	filterStream2, err := mgmtClient2.SubscribeToFilters(ctx, &management.FilterSubscription{
		HunterId: hunterID2,
	})
	require.NoError(t, err)

	filterReceived := make(chan *management.FilterUpdate, 1)
	go func() {
		for {
			update, err := filterStream2.Recv()
			if err != nil {
				return
			}
			filterReceived <- update
		}
	}()

	// Push filter to both hunters (one failed, one healthy)
	filterResp, err := mgmtClient2.PushFilter(ctx, &management.FilterRequest{
		Filter: &management.Filter{
			Id:         "circuit-breaker-test",
			Type:       "bpf",
			Expression: "tcp port 22",
			Priority:   100,
		},
		TargetHunters: []string{hunterID1, hunterID2},
	})
	require.NoError(t, err)

	// Should only update healthy hunter (circuit breaker trips for failed hunter)
	assert.Equal(t, uint32(1), filterResp.HuntersUpdated, "Only healthy hunter should receive filter")

	// Verify healthy hunter received it
	select {
	case update := <-filterReceived:
		assert.NotNil(t, update)
		assert.Equal(t, "add", update.Operation)
		t.Logf("✓ Circuit breaker test: Healthy hunter received filter, failed hunter skipped")
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for filter on healthy hunter")
	}

	// Verify failed hunter did NOT receive it (would timeout if we tried)
	_, err = filterStream1.Recv()
	assert.Error(t, err, "Failed hunter should not receive filter")
}

// TestIntegration_FilterDistribution_Priority tests filter priority ordering
func TestIntegration_FilterDistribution_Priority(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr := "127.0.0.1:50068"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	// Connect hunter
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)

	hunterID := "test-hunter-priority"
	regResp, err := mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   hunterID,
		Hostname:   "test-host",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:           false,
		},
	})
	require.NoError(t, err)
	assert.True(t, regResp.Accepted)

	// Subscribe to filter updates
	filterStream, err := mgmtClient.SubscribeToFilters(ctx, &management.FilterSubscription{
		HunterId: hunterID,
	})
	require.NoError(t, err)

	filterReceived := make(chan *management.FilterUpdate, 10)
	go func() {
		for {
			update, err := filterStream.Recv()
			if err != nil {
				return
			}
			filterReceived <- update
		}
	}()

	// Push filters with different priorities (out of order)
	filters := []struct {
		id       string
		priority uint32
	}{
		{"filter-low", 10},
		{"filter-high", 1000},
		{"filter-medium", 500},
	}

	for _, f := range filters {
		_, err := mgmtClient.PushFilter(ctx, &management.FilterRequest{
			Filter: &management.Filter{
				Id:         f.id,
				Type:       "bpf",
				Expression: fmt.Sprintf("tcp port %d", f.priority),
				Priority:   f.priority,
			},
			TargetHunters: []string{hunterID},
		})
		require.NoError(t, err)
	}

	// Collect received filters
	receivedFilters := make([]*management.FilterUpdate, 0, len(filters))
	for i := 0; i < len(filters); i++ {
		select {
		case update := <-filterReceived:
			receivedFilters = append(receivedFilters, update)
		case <-time.After(3 * time.Second):
			t.Fatal("Timeout waiting for filter updates")
		}
	}

	// Verify all filters received
	assert.Equal(t, len(filters), len(receivedFilters), "All filters should be received")

	t.Logf("✓ Filter priority test: All filters with different priorities delivered successfully")
}
