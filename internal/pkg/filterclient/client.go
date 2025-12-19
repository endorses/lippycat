// Package filterclient provides a gRPC client for managing filters on lippycat processors.
// This package is used by CLI commands for remote filter management operations.
package filterclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
)

// ClientConfig holds configuration for the filter client
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

// FilterClient provides methods for managing filters on a remote processor
type FilterClient struct {
	conn    *grpc.ClientConn
	client  management.ManagementServiceClient
	config  ClientConfig
	timeout time.Duration
}

// NewFilterClient creates a new filter client connected to a processor
func NewFilterClient(config ClientConfig) (*FilterClient, error) {
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

	return &FilterClient{
		conn:    conn,
		client:  management.NewManagementServiceClient(conn),
		config:  config,
		timeout: timeout,
	}, nil
}

// Close closes the connection to the processor
func (c *FilterClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetAddress returns the processor address
func (c *FilterClient) GetAddress() string {
	return c.config.Address
}

// context returns a context with the configured timeout
func (c *FilterClient) context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.timeout)
}
