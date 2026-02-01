//go:build processor || tap || all

package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterclient"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TestIntegration_FilterCLI_ListFilters tests listing filters via gRPC client
func TestIntegration_FilterCLI_ListFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor with dynamic port
	processorAddr, err := getFreePort()
	require.NoError(t, err, "Failed to get free port")

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err, "Failed to start processor")
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Create filter client
	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err, "Failed to create filter client")
	defer client.Close()

	// Initially, list should return empty
	filters, err := client.List(filterclient.ListOptions{})
	require.NoError(t, err, "Failed to list filters")
	assert.Empty(t, filters, "Expected no filters initially")

	// Add a filter via gRPC directly
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)
	_, err = mgmtClient.UpdateFilter(ctx, &management.Filter{
		Id:      "test-filter-1",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "alice@example.com",
		Enabled: true,
	})
	require.NoError(t, err)

	// Now list should return one filter
	filters, err = client.List(filterclient.ListOptions{})
	require.NoError(t, err, "Failed to list filters after adding")
	assert.Len(t, filters, 1, "Expected one filter after adding")
	assert.Equal(t, "test-filter-1", filters[0].Id)
	assert.Equal(t, "alice@example.com", filters[0].Pattern)

	t.Logf("✓ List filters test: Successfully listed %d filters", len(filters))
}

// TestIntegration_FilterCLI_ShowFilter tests showing a single filter
func TestIntegration_FilterCLI_ShowFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Create filter client
	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err)
	defer client.Close()

	// Try to get a non-existent filter
	_, err = client.Get("non-existent")
	assert.Error(t, err)
	assert.True(t, filterclient.IsNotFound(err), "Expected NotFoundError")

	// Add a filter
	filter := &management.Filter{
		Id:          "show-test-filter",
		Type:        management.FilterType_FILTER_PHONE_NUMBER,
		Pattern:     "+1234567890",
		Description: "Test phone filter",
		Enabled:     true,
	}
	_, err = client.Set(filter)
	require.NoError(t, err)

	// Now get should succeed
	// Note: Phone patterns are normalized (+ is stripped), so expect "1234567890" not "+1234567890"
	retrieved, err := client.Get("show-test-filter")
	require.NoError(t, err)
	assert.Equal(t, "show-test-filter", retrieved.Id)
	assert.Equal(t, "1234567890", retrieved.Pattern)
	assert.Equal(t, "Test phone filter", retrieved.Description)

	t.Logf("✓ Show filter test: Successfully retrieved filter %s", retrieved.Id)
}

// TestIntegration_FilterCLI_SetFilter tests creating and updating filters
func TestIntegration_FilterCLI_SetFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err)
	defer client.Close()

	// Create a new filter
	filter := &management.Filter{
		Id:      "set-test-filter",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "bob@example.com",
		Enabled: true,
	}
	result, err := client.Set(filter)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify filter was created
	retrieved, err := client.Get("set-test-filter")
	require.NoError(t, err)
	assert.Equal(t, "bob@example.com", retrieved.Pattern)

	// Update the filter
	filter.Pattern = "bob.updated@example.com"
	result, err = client.Set(filter)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify filter was updated
	retrieved, err = client.Get("set-test-filter")
	require.NoError(t, err)
	assert.Equal(t, "bob.updated@example.com", retrieved.Pattern)

	t.Logf("✓ Set filter test: Successfully created and updated filter")
}

// TestIntegration_FilterCLI_RmFilter tests deleting filters
func TestIntegration_FilterCLI_RmFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err)
	defer client.Close()

	// Create a filter to delete
	filter := &management.Filter{
		Id:      "rm-test-filter",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Pattern: "192.168.1.100",
		Enabled: true,
	}
	_, err = client.Set(filter)
	require.NoError(t, err)

	// Verify filter exists
	_, err = client.Get("rm-test-filter")
	require.NoError(t, err)

	// Delete the filter
	result, err := client.Delete("rm-test-filter")
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify filter is gone
	_, err = client.Get("rm-test-filter")
	assert.Error(t, err)
	assert.True(t, filterclient.IsNotFound(err))

	t.Logf("✓ Rm filter test: Successfully deleted filter")
}

// TestIntegration_FilterCLI_BatchSet tests batch filter creation
func TestIntegration_FilterCLI_BatchSet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err)
	defer client.Close()

	// Create batch of filters
	filters := []*management.Filter{
		{
			Id:      "batch-filter-1",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "user1@example.com",
			Enabled: true,
		},
		{
			Id:      "batch-filter-2",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "user2@example.com",
			Enabled: true,
		},
		{
			Id:      "batch-filter-3",
			Type:    management.FilterType_FILTER_PHONE_NUMBER,
			Pattern: "+1111111111",
			Enabled: true,
		},
	}

	result, err := client.SetBatch(filters)
	require.NoError(t, err)
	assert.Len(t, result.Succeeded, 3)
	assert.Empty(t, result.Failed)

	// Verify all filters exist
	allFilters, err := client.List(filterclient.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, allFilters, 3)

	t.Logf("✓ Batch set test: Successfully created %d filters", len(result.Succeeded))
}

// TestIntegration_FilterCLI_BatchDelete tests batch filter deletion
func TestIntegration_FilterCLI_BatchDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err)
	defer client.Close()

	// Create filters to delete
	for i := 1; i <= 5; i++ {
		filter := &management.Filter{
			Id:      filterID(i),
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "user@example.com",
			Enabled: true,
		}
		_, err := client.Set(filter)
		require.NoError(t, err)
	}

	// Verify filters exist
	allFilters, err := client.List(filterclient.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, allFilters, 5)

	// Delete batch of filters
	ids := []string{filterID(1), filterID(2), filterID(3)}
	result, err := client.DeleteBatch(ids)
	require.NoError(t, err)
	assert.Len(t, result.Succeeded, 3)
	assert.Empty(t, result.Failed)

	// Verify only 2 filters remain
	allFilters, err = client.List(filterclient.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, allFilters, 2)

	t.Logf("✓ Batch delete test: Successfully deleted %d filters", len(result.Succeeded))
}

// TestIntegration_FilterCLI_BatchFileOperations tests batch operations with YAML file
func TestIntegration_FilterCLI_BatchFileOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Create temporary YAML filter file
	tempDir := t.TempDir()
	filterFilePath := filepath.Join(tempDir, "filters.yaml")

	yamlContent := `filters:
  - id: file-filter-1
    type: sip_user
    pattern: alice@example.com
    enabled: true
  - id: file-filter-2
    type: phone_number
    pattern: "+1234567890"
    enabled: true
  - id: file-filter-3
    type: ip_address
    pattern: 10.0.0.1
    enabled: false
`
	err = os.WriteFile(filterFilePath, []byte(yamlContent), 0600)
	require.NoError(t, err)

	// Parse filter file
	filters, _, err := filtering.ParseFileWithErrors(filterFilePath)
	require.NoError(t, err)
	assert.Len(t, filters, 3)

	// Create client and set batch
	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err)
	defer client.Close()

	// Convert map to slice
	filterSlice := make([]*management.Filter, 0, len(filters))
	for _, f := range filters {
		filterSlice = append(filterSlice, f)
	}

	result, err := client.SetBatch(filterSlice)
	require.NoError(t, err)
	assert.Len(t, result.Succeeded, 3)

	// Verify filters were created
	allFilters, err := client.List(filterclient.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, allFilters, 3)

	t.Logf("✓ Batch file operations test: Successfully imported %d filters from file", len(result.Succeeded))
}

// TestIntegration_FilterCLI_TLSConnection tests filter operations over TLS
func TestIntegration_FilterCLI_TLSConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	certsDir := filepath.Join("testcerts")
	if _, err := os.Stat(filepath.Join(certsDir, "ca-cert.pem")); os.IsNotExist(err) {
		t.Skip("Skipping TLS test: certificates not found (run in integration test environment with generated certs)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start TLS-enabled processor (uses dynamic port allocation)
	procResult, err := startTLSProcessor(t, ctx, certsDir, true)
	require.NoError(t, err)
	defer procResult.proc.Shutdown()
	processorAddr := procResult.addr

	// Create filter client with TLS
	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address:     processorAddr,
		TLSEnabled:  true,
		TLSCAFile:   filepath.Join(certsDir, "ca-cert.pem"),
		TLSCertFile: filepath.Join(certsDir, "hunter-cert.pem"),
		TLSKeyFile:  filepath.Join(certsDir, "hunter-key.pem"),
	})
	require.NoError(t, err, "Failed to create TLS filter client")
	defer client.Close()

	// Test operations over TLS
	filter := &management.Filter{
		Id:      "tls-test-filter",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "secure@example.com",
		Enabled: true,
	}

	// Set filter
	result, err := client.Set(filter)
	require.NoError(t, err, "Failed to set filter over TLS")
	assert.True(t, result.Success)

	// Get filter
	retrieved, err := client.Get("tls-test-filter")
	require.NoError(t, err, "Failed to get filter over TLS")
	assert.Equal(t, "secure@example.com", retrieved.Pattern)

	// List filters
	filters, err := client.List(filterclient.ListOptions{})
	require.NoError(t, err, "Failed to list filters over TLS")
	assert.Len(t, filters, 1)

	// Delete filter
	_, err = client.Delete("tls-test-filter")
	require.NoError(t, err, "Failed to delete filter over TLS")

	t.Logf("✓ TLS connection test: All filter operations successful over TLS")
}

// TestIntegration_FilterCLI_TLSInvalidCert tests rejection of invalid TLS certificates
func TestIntegration_FilterCLI_TLSInvalidCert(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	certsDir := filepath.Join("testcerts")
	if _, err := os.Stat(filepath.Join(certsDir, "ca-cert.pem")); os.IsNotExist(err) {
		t.Skip("Skipping TLS test: certificates not found (run in integration test environment with generated certs)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start TLS-enabled processor (uses dynamic port allocation)
	procResult, err := startTLSProcessor(t, ctx, certsDir, true)
	require.NoError(t, err)
	defer procResult.proc.Shutdown()
	processorAddr := procResult.addr

	// Load CA for server verification
	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Try to connect with self-signed cert (not signed by CA)
	selfSignedCert, err := tls.X509KeyPair([]byte(selfSignedCertPEM), []byte(selfSignedKeyPEM))
	require.NoError(t, err)

	invalidCertConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{selfSignedCert},
		RootCAs:      caCertPool,
		ServerName:   "processor.test.local",
	}

	creds := credentials.NewTLS(invalidCertConfig)

	connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
	defer connCancel()

	conn, err := grpc.DialContext(connCtx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)

	if err == nil {
		// Connection succeeded, try an RPC call - it should fail
		mgmtClient := management.NewManagementServiceClient(conn)
		_, rpcErr := mgmtClient.GetFilters(connCtx, &management.FilterRequest{})
		conn.Close()

		if rpcErr == nil {
			t.Fatal("Expected RPC to fail with invalid certificate, but it succeeded")
		}
		t.Logf("RPC failed as expected with invalid cert: %v", rpcErr)
	} else {
		t.Logf("Connection failed as expected with invalid cert: %v", err)
	}

	t.Logf("✓ TLS invalid cert test: Invalid certificate correctly rejected")
}

// TestIntegration_FilterCLI_ErrorHandling tests error handling and error responses
func TestIntegration_FilterCLI_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err)
	defer client.Close()

	// Test: Get non-existent filter - should return NotFoundError
	_, err = client.Get("non-existent-filter")
	require.Error(t, err)
	assert.True(t, filterclient.IsNotFound(err), "Expected NotFoundError for non-existent filter")

	// Test: Set filter without ID - should fail
	_, err = client.Set(&management.Filter{
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "test@example.com",
	})
	require.Error(t, err)

	// Test: Delete non-existent filter - returns error (not found)
	_, err = client.Delete("non-existent-filter")
	require.Error(t, err, "Deleting non-existent filter should return error")

	// Test: Batch with some empty IDs
	batchResult, err := client.SetBatch([]*management.Filter{
		{
			Id:      "valid-filter",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "valid@example.com",
			Enabled: true,
		},
		{
			Id:      "", // Empty ID should fail
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "invalid@example.com",
			Enabled: true,
		},
	})
	require.NoError(t, err)
	assert.Len(t, batchResult.Succeeded, 1, "One filter should succeed")
	assert.Len(t, batchResult.Failed, 1, "One filter should fail")

	t.Logf("✓ Error handling test: All error cases handled correctly")
}

// TestIntegration_FilterCLI_ConnectionError tests connection error handling
func TestIntegration_FilterCLI_ConnectionError(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Try to connect to a non-existent processor
	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: "127.0.0.1:59999", // Port that should not be listening
		Timeout: 2 * time.Second,
	})

	// The client may be created but operations will fail
	if err != nil {
		// Connection failed immediately - this is expected
		t.Logf("Connection failed as expected: %v", err)
	} else {
		defer client.Close()
		// Try to list filters - should fail
		_, err = client.List(filterclient.ListOptions{})
		require.Error(t, err, "Expected connection error when listing from non-existent processor")
		t.Logf("Operation failed as expected: %v", err)
	}

	t.Logf("✓ Connection error test: Connection errors handled correctly")
}

// TestIntegration_FilterCLI_FilterTypeValidation tests filter type parsing
func TestIntegration_FilterCLI_FilterTypeValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test valid filter types
	validTypes := map[string]management.FilterType{
		"sip_user":     management.FilterType_FILTER_SIP_USER,
		"phone_number": management.FilterType_FILTER_PHONE_NUMBER,
		"ip_address":   management.FilterType_FILTER_IP_ADDRESS,
		"call_id":      management.FilterType_FILTER_CALL_ID,
		"codec":        management.FilterType_FILTER_CODEC,
		"bpf":          management.FilterType_FILTER_BPF,
	}

	for typeName, expectedType := range validTypes {
		parsed, err := filtering.ParseFilterType(typeName)
		require.NoError(t, err, "Failed to parse valid filter type: %s", typeName)
		assert.Equal(t, expectedType, parsed, "Mismatch for filter type: %s", typeName)
	}

	// Test invalid filter type
	_, err := filtering.ParseFilterType("invalid_type")
	require.Error(t, err, "Expected error for invalid filter type")

	t.Logf("✓ Filter type validation test: All filter types parsed correctly")
}

// TestIntegration_FilterCLI_HunterTargeting tests filter targeting specific hunters
func TestIntegration_FilterCLI_HunterTargeting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Register test hunters
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)

	for _, hunterID := range []string{"hunter-1", "hunter-2", "hunter-3"} {
		_, err := mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
			HunterId:   hunterID,
			Hostname:   hunterID + "-host",
			Interfaces: []string{"eth0"},
			Version:    "test-1.0.0",
			Capabilities: &management.HunterCapabilities{
				FilterTypes:     []string{"bpf", "sip_user", "phone_number", "call_id", "codec"},
				MaxBufferSize:   8192,
				GpuAcceleration: false,
				AfXdp:           false,
			},
		})
		require.NoError(t, err)
	}

	// Create filter client
	client, err := filterclient.NewFilterClient(filterclient.ClientConfig{
		Address: processorAddr,
	})
	require.NoError(t, err)
	defer client.Close()

	// Create filter targeting specific hunters
	filter := &management.Filter{
		Id:            "targeted-filter",
		Type:          management.FilterType_FILTER_SIP_USER,
		Pattern:       "targeted@example.com",
		TargetHunters: []string{"hunter-1", "hunter-2"},
		Enabled:       true,
	}

	result, err := client.Set(filter)
	require.NoError(t, err)
	assert.True(t, result.Success)
	// Note: HuntersUpdated is 0 because hunters are only registered, not subscribed to filter updates
	// The actual filter distribution is tested in filter_distribution_integration_test.go

	// Verify filter was created with target hunters
	retrieved, err := client.Get("targeted-filter")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"hunter-1", "hunter-2"}, retrieved.TargetHunters)

	t.Logf("✓ Hunter targeting test: Filter created with %d target hunters", len(retrieved.TargetHunters))
}

// filterID generates a filter ID for testing
func filterID(n int) string {
	return "batch-delete-filter-" + string(rune('0'+n))
}
