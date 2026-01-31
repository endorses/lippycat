package filterclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/endorses/lippycat/api/gen/management"
)

// mockManagementServer implements the ManagementService for testing
type mockManagementServer struct {
	management.UnimplementedManagementServiceServer

	filters []*management.Filter

	// Control behavior
	getFiltersErr    error
	updateFilterErr  error
	deleteFilterErr  error
	updateFilterResp *management.FilterUpdateResult
	deleteFilterResp *management.FilterUpdateResult
}

func newMockServer() *mockManagementServer {
	return &mockManagementServer{
		filters: make([]*management.Filter, 0),
		updateFilterResp: &management.FilterUpdateResult{
			Success:        true,
			HuntersUpdated: 1,
		},
		deleteFilterResp: &management.FilterUpdateResult{
			Success:        true,
			HuntersUpdated: 1,
		},
	}
}

func (m *mockManagementServer) GetFilters(_ context.Context, _ *management.FilterRequest) (*management.FilterResponse, error) {
	if m.getFiltersErr != nil {
		return nil, m.getFiltersErr
	}
	return &management.FilterResponse{Filters: m.filters}, nil
}

func (m *mockManagementServer) UpdateFilter(_ context.Context, filter *management.Filter) (*management.FilterUpdateResult, error) {
	if m.updateFilterErr != nil {
		return nil, m.updateFilterErr
	}

	// Update or add filter
	found := false
	for i, f := range m.filters {
		if f.Id == filter.Id {
			m.filters[i] = filter
			found = true
			break
		}
	}
	if !found {
		m.filters = append(m.filters, filter)
	}

	return m.updateFilterResp, nil
}

func (m *mockManagementServer) DeleteFilter(_ context.Context, req *management.FilterDeleteRequest) (*management.FilterUpdateResult, error) {
	if m.deleteFilterErr != nil {
		return nil, m.deleteFilterErr
	}

	// Remove filter
	for i, f := range m.filters {
		if f.Id == req.FilterId {
			m.filters = append(m.filters[:i], m.filters[i+1:]...)
			break
		}
	}

	return m.deleteFilterResp, nil
}

// startMockServer starts a mock gRPC server and returns the address and cleanup function
func startMockServer(t *testing.T, mock *mockManagementServer) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	management.RegisterManagementServiceServer(server, mock)

	go func() {
		if serveErr := server.Serve(listener); serveErr != nil {
			// Ignore errors after server is stopped
		}
	}()

	cleanup := func() {
		server.Stop()
	}

	return listener.Addr().String(), cleanup
}

func TestNewFilterClient(t *testing.T) {
	mock := newMockServer()
	addr, cleanup := startMockServer(t, mock)
	defer cleanup()

	t.Run("success", func(t *testing.T) {
		client, err := NewFilterClient(ClientConfig{
			Address: addr,
			Timeout: 5 * time.Second,
		})
		require.NoError(t, err)
		defer func() {
			_ = client.Close()
		}()

		assert.NotNil(t, client)
		assert.Equal(t, addr, client.GetAddress())
	})

	t.Run("empty address", func(t *testing.T) {
		_, err := NewFilterClient(ClientConfig{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "processor address is required")
	})

	t.Run("default timeout", func(t *testing.T) {
		client, err := NewFilterClient(ClientConfig{
			Address: addr,
		})
		require.NoError(t, err)
		defer func() {
			_ = client.Close()
		}()

		assert.Equal(t, 30*time.Second, client.timeout)
	})
}

func TestFilterClient_Close(t *testing.T) {
	mock := newMockServer()
	addr, cleanup := startMockServer(t, mock)
	defer cleanup()

	client, err := NewFilterClient(ClientConfig{
		Address: addr,
	})
	require.NoError(t, err)

	// Close should not error
	err = client.Close()
	assert.NoError(t, err)

	// Close on nil conn should not error
	client.conn = nil
	err = client.Close()
	assert.NoError(t, err)
}

func TestClientConfig_TLS(t *testing.T) {
	t.Run("tls with invalid cert file fails", func(t *testing.T) {
		// This should fail because the cert file doesn't exist
		_, err := NewFilterClient(ClientConfig{
			Address:     "localhost:55555",
			TLSEnabled:  true,
			TLSCertFile: "/nonexistent/cert.pem",
			TLSKeyFile:  "/nonexistent/key.pem",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to build TLS credentials")
	})

	t.Run("tls with only cert fails", func(t *testing.T) {
		// This should fail because only cert is provided (not key)
		_, err := NewFilterClient(ClientConfig{
			Address:     "localhost:55555",
			TLSEnabled:  true,
			TLSCertFile: "/some/cert.pem",
			// Missing key file
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to build TLS credentials")
	})
}

// createTestClient creates a client connected to a mock server for testing
func createTestClient(t *testing.T, mock *mockManagementServer) (*FilterClient, func()) {
	t.Helper()

	addr, serverCleanup := startMockServer(t, mock)

	// Create a client that connects directly
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client := &FilterClient{
		conn:    conn,
		client:  management.NewManagementServiceClient(conn),
		config:  ClientConfig{Address: addr},
		timeout: 5 * time.Second,
	}

	cleanup := func() {
		_ = client.Close()
		serverCleanup()
	}

	return client, cleanup
}
