// Package statusclient provides a gRPC client for querying processor status.
// This package is used by CLI commands for remote status monitoring.
package statusclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
)

// ClientConfig holds configuration for the status client
type ClientConfig struct {
	// Address of the processor (host:port)
	Address string

	// TLS settings
	TLSEnabled    bool   // Enable TLS encryption
	TLSCAFile     string // Path to CA certificate file
	TLSCertFile   string // Path to client certificate file (for mutual TLS)
	TLSKeyFile    string // Path to client key file (for mutual TLS)
	TLSSkipVerify bool   // Skip certificate verification (insecure, for testing only)

	// Timeout for operations (default: 30s)
	Timeout time.Duration
}

// StatusClient provides methods for querying status on a remote processor
type StatusClient struct {
	conn    *grpc.ClientConn
	client  management.ManagementServiceClient
	config  ClientConfig
	timeout time.Duration
}

// NewStatusClient creates a new status client connected to a processor
func NewStatusClient(config ClientConfig) (*StatusClient, error) {
	if config.Address == "" {
		return nil, fmt.Errorf("processor address is required")
	}

	// Set default timeout
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Build dial options
	opts := []grpc.DialOption{}

	// Configure TLS if enabled
	if config.TLSEnabled {
		tlsCreds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
			CAFile:     config.TLSCAFile,
			CertFile:   config.TLSCertFile,
			KeyFile:    config.TLSKeyFile,
			SkipVerify: config.TLSSkipVerify,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(tlsCreds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Connect to processor
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, config.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to processor %s: %w", config.Address, err)
	}

	return &StatusClient{
		conn:    conn,
		client:  management.NewManagementServiceClient(conn),
		config:  config,
		timeout: timeout,
	}, nil
}

// Close closes the connection to the processor
func (c *StatusClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetAddress returns the processor address
func (c *StatusClient) GetAddress() string {
	return c.config.Address
}

// context returns a context with the configured timeout
func (c *StatusClient) context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.timeout)
}

// GetStatus retrieves processor status and hunter summary
func (c *StatusClient) GetStatus() (*management.StatusResponse, error) {
	ctx, cancel := c.context()
	defer cancel()

	resp, err := c.client.GetHunterStatus(ctx, &management.StatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %w", err)
	}

	return resp, nil
}

// GetHunters retrieves connected hunter details
// If hunterID is provided, filters to that specific hunter
func (c *StatusClient) GetHunters(hunterID string) ([]*management.ConnectedHunter, error) {
	ctx, cancel := c.context()
	defer cancel()

	resp, err := c.client.GetHunterStatus(ctx, &management.StatusRequest{
		HunterId: hunterID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get hunters: %w", err)
	}

	return resp.Hunters, nil
}

// GetTopology retrieves the full distributed topology
func (c *StatusClient) GetTopology() (*management.TopologyResponse, error) {
	ctx, cancel := c.context()
	defer cancel()

	resp, err := c.client.GetTopology(ctx, &management.TopologyRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get topology: %w", err)
	}

	return resp, nil
}
