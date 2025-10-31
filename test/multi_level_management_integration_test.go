package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// TestIntegration_MultiLevel_FilterUpdate2Level tests filter updates through 2-level hierarchy
// Topology: Root Processor → Downstream Processor → Hunter
func TestIntegration_MultiLevel_FilterUpdate2Level(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Start root processor
	rootAddr := "127.0.0.1:51001"
	rootProc, rootConn, err := startProcessorHierarchy(ctx, rootAddr, "root-proc", "")
	require.NoError(t, err, "Failed to start root processor")
	defer shutdownProcessorWithPortCleanup(rootProc)
	if rootConn != nil {
		defer rootConn.Close()
	}

	// Start downstream processor connected to root
	downstreamAddr := "127.0.0.1:51002"
	downstreamProc, downstreamConn, err := startProcessorHierarchy(ctx, downstreamAddr, "downstream-proc", rootAddr)
	require.NoError(t, err, "Failed to start downstream processor")
	defer shutdownProcessorWithPortCleanup(downstreamProc)
	defer downstreamConn.Close()

	time.Sleep(3 * time.Second) // Wait for hierarchy to stabilize (allows for retry backoff)

	// Connect hunter to downstream processor
	hunterConn, hunterStream, err := connectHunter(ctx, downstreamAddr, "test-hunter-2level")
	require.NoError(t, err, "Failed to connect hunter to downstream")
	defer hunterConn.Close()

	// Subscribe to filter updates
	mgmtClient := management.NewManagementServiceClient(hunterConn)
	filterStream, err := mgmtClient.SubscribeFilters(ctx, &management.FilterRequest{
		HunterId: "test-hunter-2level",
	})
	require.NoError(t, err, "Failed to subscribe to filters")

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

	// Send filter update from root processor targeting downstream hunter
	rootMgmtConn, err := grpc.DialContext(ctx, rootAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to root processor")
	defer rootMgmtConn.Close()

	rootMgmtClient := management.NewManagementServiceClient(rootMgmtConn)

	// Create filter targeted at downstream processor
	filter := &management.Filter{
		Id:            "filter-2level",
		Type:          management.FilterType_FILTER_SIP_USER,
		Pattern:       "alice@example.com",
		TargetHunters: []string{"test-hunter-2level"},
		Enabled:       true,
	}

	result, err := rootMgmtClient.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
		ProcessorId: "downstream-proc",
		Filter:      filter,
	})
	require.NoError(t, err, "Filter update through 2-level hierarchy should succeed")
	assert.True(t, result.Success, "Filter update should report success")

	// Verify hunter received the filter
	select {
	case update := <-filterReceived:
		assert.NotNil(t, update)
		assert.Equal(t, management.FilterUpdateType_UPDATE_ADD, update.UpdateType)
		assert.Equal(t, "filter-2level", update.Filter.Id)
		assert.Equal(t, "alice@example.com", update.Filter.Pattern)
		t.Logf("✓ 2-level filter update test: Filter successfully propagated through hierarchy")
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for filter update through 2-level hierarchy")
	}

	// Keep stream active
	_ = hunterStream
}

// TestIntegration_MultiLevel_FilterUpdate3Level tests filter updates through 3-level hierarchy
// Topology: Root → Intermediate → Leaf Processor → Hunter
func TestIntegration_MultiLevel_FilterUpdate3Level(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start root processor
	rootAddr := "127.0.0.1:51011"
	rootProc, rootConn, err := startProcessorHierarchy(ctx, rootAddr, "root-proc-3l", "")
	require.NoError(t, err, "Failed to start root processor")
	defer shutdownProcessorWithPortCleanup(rootProc)
	if rootConn != nil {
		defer rootConn.Close()
	}

	// Start intermediate processor connected to root
	intermediateAddr := "127.0.0.1:51012"
	intermediateProc, intermediateConn, err := startProcessorHierarchy(ctx, intermediateAddr, "intermediate-proc", rootAddr)
	require.NoError(t, err, "Failed to start intermediate processor")
	defer shutdownProcessorWithPortCleanup(intermediateProc)
	defer intermediateConn.Close()

	// Start leaf processor connected to intermediate
	leafAddr := "127.0.0.1:51013"
	leafProc, leafConn, err := startProcessorHierarchy(ctx, leafAddr, "leaf-proc", intermediateAddr)
	require.NoError(t, err, "Failed to start leaf processor")
	defer shutdownProcessorWithPortCleanup(leafProc)
	defer leafConn.Close()

	time.Sleep(6 * time.Second) // Wait for 3-level hierarchy to stabilize (allows for retry backoff)

	// Connect hunter to leaf processor
	hunterConn, hunterStream, err := connectHunter(ctx, leafAddr, "test-hunter-3level")
	require.NoError(t, err, "Failed to connect hunter to leaf")
	defer hunterConn.Close()

	// Subscribe to filter updates
	mgmtClient := management.NewManagementServiceClient(hunterConn)
	filterStream, err := mgmtClient.SubscribeFilters(ctx, &management.FilterRequest{
		HunterId: "test-hunter-3level",
	})
	require.NoError(t, err, "Failed to subscribe to filters")

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

	// Send filter update from root processor targeting leaf hunter
	rootMgmtConn, err := grpc.DialContext(ctx, rootAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to root processor")
	defer rootMgmtConn.Close()

	rootMgmtClient := management.NewManagementServiceClient(rootMgmtConn)

	// Create filter targeted at leaf processor
	filter := &management.Filter{
		Id:            "filter-3level",
		Type:          management.FilterType_FILTER_SIP_USER,
		Pattern:       "bob@example.com",
		TargetHunters: []string{"test-hunter-3level"},
		Enabled:       true,
	}

	result, err := rootMgmtClient.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
		ProcessorId: "leaf-proc",
		Filter:      filter,
	})
	require.NoError(t, err, "Filter update through 3-level hierarchy should succeed")
	assert.True(t, result.Success, "Filter update should report success")

	// Verify hunter received the filter
	select {
	case update := <-filterReceived:
		assert.NotNil(t, update)
		assert.Equal(t, management.FilterUpdateType_UPDATE_ADD, update.UpdateType)
		assert.Equal(t, "filter-3level", update.Filter.Id)
		assert.Equal(t, "bob@example.com", update.Filter.Pattern)
		t.Logf("✓ 3-level filter update test: Filter successfully propagated through deep hierarchy")
	case <-time.After(8 * time.Second):
		t.Fatal("Timeout waiting for filter update through 3-level hierarchy")
	}

	// Keep stream active
	_ = hunterStream
}

// TestIntegration_MultiLevel_FilterDelete tests filter deletion through hierarchy
func TestIntegration_MultiLevel_FilterDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Start root processor
	rootAddr := "127.0.0.1:51021"
	rootProc, rootConn, err := startProcessorHierarchy(ctx, rootAddr, "root-proc-del", "")
	require.NoError(t, err, "Failed to start root processor")
	defer shutdownProcessorWithPortCleanup(rootProc)
	if rootConn != nil {
		defer rootConn.Close()
	}

	// Start downstream processor
	downstreamAddr := "127.0.0.1:51022"
	downstreamProc, downstreamConn, err := startProcessorHierarchy(ctx, downstreamAddr, "downstream-proc-del", rootAddr)
	require.NoError(t, err, "Failed to start downstream processor")
	defer shutdownProcessorWithPortCleanup(downstreamProc)
	defer downstreamConn.Close()

	time.Sleep(2 * time.Second)

	// Connect hunter
	hunterConn, hunterStream, err := connectHunter(ctx, downstreamAddr, "test-hunter-delete")
	require.NoError(t, err, "Failed to connect hunter")
	defer hunterConn.Close()

	// Subscribe to filter updates
	mgmtClient := management.NewManagementServiceClient(hunterConn)
	filterStream, err := mgmtClient.SubscribeFilters(ctx, &management.FilterRequest{
		HunterId: "test-hunter-delete",
	})
	require.NoError(t, err, "Failed to subscribe to filters")

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

	// Connect to root processor
	rootMgmtConn, err := grpc.DialContext(ctx, rootAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to root processor")
	defer rootMgmtConn.Close()

	rootMgmtClient := management.NewManagementServiceClient(rootMgmtConn)

	// 1. Add filter
	filter := &management.Filter{
		Id:            "filter-delete-test",
		Type:          management.FilterType_FILTER_SIP_USER,
		Pattern:       "charlie@example.com",
		TargetHunters: []string{"test-hunter-delete"},
		Enabled:       true,
	}

	_, err = rootMgmtClient.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
		ProcessorId: "downstream-proc-del",
		Filter:      filter,
	})
	require.NoError(t, err, "Filter add should succeed")

	// Verify ADD
	select {
	case update := <-filterReceived:
		assert.Equal(t, management.FilterUpdateType_UPDATE_ADD, update.UpdateType)
		assert.Equal(t, "filter-delete-test", update.Filter.Id)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for filter add")
	}

	// 2. Delete filter
	result, err := rootMgmtClient.DeleteFilterOnProcessor(ctx, &management.ProcessorFilterDeleteRequest{
		ProcessorId: "downstream-proc-del",
		FilterId:    "filter-delete-test",
	})
	require.NoError(t, err, "Filter delete through hierarchy should succeed")
	assert.True(t, result.Success, "Filter delete should report success")

	// Verify DELETE
	select {
	case update := <-filterReceived:
		assert.Equal(t, management.FilterUpdateType_UPDATE_DELETE, update.UpdateType)
		assert.Equal(t, "filter-delete-test", update.Filter.Id)
		t.Logf("✓ Filter delete test: Successfully deleted filter through hierarchy")
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for filter delete")
	}

	// Keep stream active
	_ = hunterStream
}

// TestIntegration_MultiLevel_ExpiredToken tests that operations with expired tokens are rejected
func TestIntegration_MultiLevel_ExpiredToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processors
	rootAddr := "127.0.0.1:51031"
	rootProc, rootConn, err := startProcessorHierarchy(ctx, rootAddr, "root-proc-expiry", "")
	require.NoError(t, err, "Failed to start root processor")
	defer shutdownProcessorWithPortCleanup(rootProc)
	if rootConn != nil {
		defer rootConn.Close()
	}

	downstreamAddr := "127.0.0.1:51032"
	downstreamProc, downstreamConn, err := startProcessorHierarchy(ctx, downstreamAddr, "downstream-proc-expiry", rootAddr)
	require.NoError(t, err, "Failed to start downstream processor")
	defer shutdownProcessorWithPortCleanup(downstreamProc)
	defer downstreamConn.Close()

	time.Sleep(2 * time.Second)

	// Create an expired token
	expiredToken := &management.AuthorizationToken{
		Signature:         []byte("fake-signature"),
		IssuedAtNs:        time.Now().Add(-10 * time.Minute).UnixNano(),
		ExpiresAtNs:       time.Now().Add(-5 * time.Minute).UnixNano(), // Expired 5 minutes ago
		TargetProcessorId: "downstream-proc-expiry",
		IssuerId:          "root-proc-expiry",
		ProcessorChain:    []string{"root-proc-expiry", "downstream-proc-expiry"},
	}

	// Connect to downstream processor
	downstreamMgmtConn, err := grpc.DialContext(ctx, downstreamAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to downstream processor")
	defer downstreamMgmtConn.Close()

	downstreamMgmtClient := management.NewManagementServiceClient(downstreamMgmtConn)

	// Attempt to use expired token (directly on downstream processor)
	filter := &management.Filter{
		Id:            "filter-expired",
		Type:          management.FilterType_FILTER_SIP_USER,
		Pattern:       "expired@example.com",
		TargetHunters: []string{},
		Enabled:       true,
	}

	_, err = downstreamMgmtClient.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
		ProcessorId: "downstream-proc-expiry",
		Filter:      filter,
		AuthToken:   expiredToken,
	})

	// Should fail with unauthenticated error
	require.Error(t, err, "Operation with expired token should fail")
	st, ok := status.FromError(err)
	require.True(t, ok, "Error should be a gRPC status error")
	assert.Equal(t, codes.Unauthenticated, st.Code(), "Should return Unauthenticated error for expired token")

	t.Logf("✓ Expired token test: Operation correctly rejected with error: %v", st.Message())
}

// TestIntegration_MultiLevel_InvalidToken tests that operations with invalid tokens are rejected
func TestIntegration_MultiLevel_InvalidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processors with TLS credentials
	rootAddr := "127.0.0.1:51041"
	rootProc, rootConn, err := startProcessorHierarchyWithTLS(ctx, rootAddr, "root-proc-invalid", "")
	require.NoError(t, err, "Failed to start root processor with TLS")
	defer shutdownProcessorWithPortCleanup(rootProc)
	if rootConn != nil {
		defer rootConn.Close()
	}

	downstreamAddr := "127.0.0.1:51042"
	downstreamProc, downstreamConn, err := startProcessorHierarchyWithTLS(ctx, downstreamAddr, "downstream-proc-invalid", rootAddr)
	require.NoError(t, err, "Failed to start downstream processor with TLS")
	defer shutdownProcessorWithPortCleanup(downstreamProc)
	defer downstreamConn.Close()

	time.Sleep(2 * time.Second)

	// Create a token with invalid signature
	invalidToken := &management.AuthorizationToken{
		Signature:         []byte("completely-invalid-signature"),
		IssuedAtNs:        time.Now().UnixNano(),
		ExpiresAtNs:       time.Now().Add(5 * time.Minute).UnixNano(),
		TargetProcessorId: "downstream-proc-invalid",
		IssuerId:          "root-proc-invalid",
		ProcessorChain:    []string{"root-proc-invalid", "downstream-proc-invalid"},
	}

	// Connect to downstream processor
	downstreamMgmtConn, err := grpc.DialContext(ctx, downstreamAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to downstream processor")
	defer downstreamMgmtConn.Close()

	downstreamMgmtClient := management.NewManagementServiceClient(downstreamMgmtConn)

	// Attempt to use invalid token
	filter := &management.Filter{
		Id:            "filter-invalid",
		Type:          management.FilterType_FILTER_SIP_USER,
		Pattern:       "invalid@example.com",
		TargetHunters: []string{},
		Enabled:       true,
	}

	_, err = downstreamMgmtClient.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
		ProcessorId: "downstream-proc-invalid",
		Filter:      filter,
		AuthToken:   invalidToken,
	})

	// Should fail with unauthenticated error
	require.Error(t, err, "Operation with invalid token should fail")
	st, ok := status.FromError(err)
	require.True(t, ok, "Error should be a gRPC status error")
	assert.Equal(t, codes.Unauthenticated, st.Code(), "Should return Unauthenticated error for invalid token")

	t.Logf("✓ Invalid token test: Operation correctly rejected with error: %v", st.Message())
}

// TestIntegration_MultiLevel_NonExistentProcessor tests error handling for non-existent processors
func TestIntegration_MultiLevel_NonExistentProcessor(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start root processor only
	rootAddr := "127.0.0.1:51051"
	rootProc, rootConn, err := startProcessorHierarchy(ctx, rootAddr, "root-proc-nonexist", "")
	require.NoError(t, err, "Failed to start root processor")
	defer shutdownProcessorWithPortCleanup(rootProc)
	if rootConn != nil {
		defer rootConn.Close()
	}

	time.Sleep(500 * time.Millisecond)

	// Connect to root processor
	rootMgmtConn, err := grpc.DialContext(ctx, rootAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to root processor")
	defer rootMgmtConn.Close()

	rootMgmtClient := management.NewManagementServiceClient(rootMgmtConn)

	// Attempt to send operation to non-existent processor
	filter := &management.Filter{
		Id:            "filter-nonexist",
		Type:          management.FilterType_FILTER_SIP_USER,
		Pattern:       "nonexist@example.com",
		TargetHunters: []string{},
		Enabled:       true,
	}

	_, err = rootMgmtClient.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
		ProcessorId: "non-existent-processor",
		Filter:      filter,
	})

	// Should fail with NotFound error
	require.Error(t, err, "Operation on non-existent processor should fail")
	st, ok := status.FromError(err)
	require.True(t, ok, "Error should be a gRPC status error")
	assert.Equal(t, codes.NotFound, st.Code(), "Should return NotFound error for non-existent processor")

	t.Logf("✓ Non-existent processor test: Operation correctly rejected with error: %v", st.Message())
}

// TestIntegration_MultiLevel_HierarchyDepthLimit tests that processor registration is rejected when depth exceeds maximum
func TestIntegration_MultiLevel_HierarchyDepthLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start root processor (depth 0)
	rootAddr := "127.0.0.1:51061"
	rootProc, rootConn, err := startProcessorHierarchy(ctx, rootAddr, "root-proc-depth", "")
	require.NoError(t, err, "Failed to start root processor")
	defer shutdownProcessorWithPortCleanup(rootProc)
	if rootConn != nil {
		defer rootConn.Close()
	}

	// Build a chain of processors up to depth 10 (MaxHierarchyDepth)
	// We'll create 10 levels, where the last one is at depth 10
	basePort := 51062
	processors := []*processor.Processor{rootProc}
	connections := []*grpc.ClientConn{}
	upstreamChain := []string{}

	for i := 1; i <= 10; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", basePort+i-1)
		processorID := fmt.Sprintf("proc-depth-%d", i)
		upstreamAddr := fmt.Sprintf("127.0.0.1:%d", basePort+i-2)
		if i == 1 {
			upstreamAddr = rootAddr
		}

		// Connect to upstream
		upstreamConn, err := grpc.DialContext(ctx, upstreamAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(t, err, "Failed to connect to upstream at level %d", i)

		// Register processor with upstream_chain
		mgmtClient := management.NewManagementServiceClient(upstreamConn)
		resp, err := mgmtClient.RegisterProcessor(ctx, &management.ProcessorRegistration{
			ProcessorId:   processorID,
			ListenAddress: addr,
			Version:       "test-1.0.0",
			UpstreamChain: upstreamChain,
		})
		require.NoError(t, err, "Failed to register processor at level %d", i)
		require.True(t, resp.Accepted, "Processor at level %d should be accepted (depth=%d)", i, i)

		// Start the processor
		config := processor.Config{
			ProcessorID:     processorID,
			ListenAddr:      addr,
			UpstreamAddr:    upstreamAddr,
			EnableDetection: false,
			MaxHunters:      100,
		}

		proc, err := processor.New(config)
		require.NoError(t, err, "Failed to create processor at level %d", i)

		errChan := make(chan error, 1)
		go func() {
			if err := proc.Start(ctx); err != nil {
				select {
				case errChan <- err:
				default:
				}
			}
		}()

		// Wait for processor to start
		select {
		case err := <-errChan:
			upstreamConn.Close()
			require.NoError(t, err, "Processor at level %d failed to start", i)
		case <-time.After(2 * time.Second):
			// Started successfully
		}

		processors = append(processors, proc)
		connections = append(connections, upstreamConn)

		// Build upstream chain for next level (add current processor's parent)
		if i == 1 {
			upstreamChain = []string{"root-proc-depth"}
		} else {
			upstreamChain = append(upstreamChain, fmt.Sprintf("proc-depth-%d", i-1))
		}

		t.Logf("✓ Created processor at depth %d: %s", i, processorID)
	}

	// Now attempt to register an 11th processor (depth 11, which exceeds MaxHierarchyDepth=10)
	level11Addr := fmt.Sprintf("127.0.0.1:%d", basePort+10)
	level11ID := "proc-depth-11"
	level10Addr := fmt.Sprintf("127.0.0.1:%d", basePort+9)

	// Connect to level 10 processor
	level10Conn, err := grpc.DialContext(ctx, level10Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to level 10 processor")
	defer level10Conn.Close()

	// Build upstream chain for level 11 (includes all processors from root to level 10)
	level11UpstreamChain := []string{"root-proc-depth"}
	for i := 1; i <= 10; i++ {
		level11UpstreamChain = append(level11UpstreamChain, fmt.Sprintf("proc-depth-%d", i))
	}

	// Attempt to register level 11 processor (should be rejected)
	mgmtClient := management.NewManagementServiceClient(level10Conn)
	resp, err := mgmtClient.RegisterProcessor(ctx, &management.ProcessorRegistration{
		ProcessorId:   level11ID,
		ListenAddress: level11Addr,
		Version:       "test-1.0.0",
		UpstreamChain: level11UpstreamChain,
	})

	// Should succeed in getting a response, but registration should be rejected
	require.NoError(t, err, "RegisterProcessor RPC should succeed")
	require.NotNil(t, resp, "Response should not be nil")
	assert.False(t, resp.Accepted, "Registration at depth 11 should be rejected")
	assert.Contains(t, resp.Error, "hierarchy depth", "Error message should mention hierarchy depth")
	assert.Contains(t, resp.Error, "exceeds maximum", "Error message should mention exceeding maximum")

	t.Logf("✓ Level 11 processor correctly rejected with error: %s", resp.Error)

	// Clean up all processors and connections
	for i := len(processors) - 1; i >= 0; i-- {
		if i > 0 { // Skip root processor (will be cleaned by defer)
			shutdownProcessorWithPortCleanup(processors[i])
		}
	}
	for _, conn := range connections {
		conn.Close()
	}
}

// Helper functions

// startProcessorHierarchy starts a processor and optionally connects it to an upstream processor
func startProcessorHierarchy(ctx context.Context, addr, processorID, upstreamAddr string) (*processor.Processor, *grpc.ClientConn, error) {
	config := processor.Config{
		ProcessorID:     processorID,
		ListenAddr:      addr,
		EnableDetection: false,
		MaxHunters:      100,
	}

	// If upstream address is provided, configure as downstream processor
	var upstreamConn *grpc.ClientConn
	if upstreamAddr != "" {
		var err error
		upstreamConn, err = grpc.DialContext(ctx, upstreamAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to upstream %s: %w", upstreamAddr, err)
		}

		config.UpstreamAddr = upstreamAddr

		// Register this processor with upstream
		mgmtClient := management.NewManagementServiceClient(upstreamConn)
		_, err = mgmtClient.RegisterProcessor(ctx, &management.ProcessorRegistration{
			ProcessorId:   processorID,
			ListenAddress: addr,
			Version:       "test-1.0.0",
			UpstreamChain: []string{},
		})
		if err != nil {
			upstreamConn.Close()
			return nil, nil, fmt.Errorf("failed to register with upstream: %w", err)
		}
	}

	proc, err := processor.New(config)
	if err != nil {
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		return nil, nil, err
	}

	// Start processor in background
	errChan := make(chan error, 1)
	go func() {
		if err := proc.Start(ctx); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
	}()

	// Wait and check for startup errors
	select {
	case err := <-errChan:
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		return nil, nil, fmt.Errorf("processor failed to start: %w", err)
	case <-time.After(2 * time.Second):
		// Processor started successfully (wait to ensure gRPC server is fully listening and accepting connections)
	}

	return proc, upstreamConn, nil
}

// startProcessorHierarchyWithTLS starts a processor with TLS credentials configured
func startProcessorHierarchyWithTLS(ctx context.Context, addr, processorID, upstreamAddr string) (*processor.Processor, *grpc.ClientConn, error) {
	// Generate self-signed certificate for testing
	cert, key, err := generateTestCertificate(processorID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate test certificate: %w", err)
	}

	config := processor.Config{
		ProcessorID:     processorID,
		ListenAddr:      addr,
		EnableDetection: false,
		MaxHunters:      100,
	}

	// If upstream address is provided, configure as downstream processor
	var upstreamConn *grpc.ClientConn
	if upstreamAddr != "" {
		var err error
		upstreamConn, err = grpc.DialContext(ctx, upstreamAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to upstream %s: %w", upstreamAddr, err)
		}

		config.UpstreamAddr = upstreamAddr

		// Register this processor with upstream
		mgmtClient := management.NewManagementServiceClient(upstreamConn)
		_, err = mgmtClient.RegisterProcessor(ctx, &management.ProcessorRegistration{
			ProcessorId:   processorID,
			ListenAddress: addr,
			Version:       "test-1.0.0",
			UpstreamChain: []string{},
		})
		if err != nil {
			upstreamConn.Close()
			return nil, nil, fmt.Errorf("failed to register with upstream: %w", err)
		}
	}

	proc, err := processor.New(config)
	if err != nil {
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		return nil, nil, err
	}

	// Set TLS credentials on proxy manager
	proc.SetProxyTLSCredentials(cert, key)

	// Start processor in background
	errChan := make(chan error, 1)
	go func() {
		if err := proc.Start(ctx); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
	}()

	// Wait and check for startup errors
	select {
	case err := <-errChan:
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		return nil, nil, fmt.Errorf("processor failed to start: %w", err)
	case <-time.After(2 * time.Second):
		// Processor started successfully (wait to ensure gRPC server is fully listening and accepting connections)
	}

	return proc, upstreamConn, nil
}

// generateTestCertificate generates a self-signed certificate for testing
func generateTestCertificate(commonName string) (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return certPEM, keyPEM, nil
}

// Verify that proxy.TokenTTL exists for our test reference
var _ = proxy.TokenTTL
