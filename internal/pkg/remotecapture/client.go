// Package remotecapture provides a client for connecting to remote processors
// and subscribing to packet streams, hunter status, and topology updates.
//
// File: client.go - Core types, constructor, and lifecycle management
//
// This file contains the fundamental client types, configuration, constructor,
// connection management, and node type detection. Related functionality is split
// across companion files:
//   - client_streaming.go: Packet streaming and hot-swapping
//   - client_subscriptions.go: Hunter status, topology, and call subscriptions
//   - client_conversion.go: Packet parsing and state conversion
package remotecapture

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// NodeType represents the type of remote node
type NodeType int

const (
	NodeTypeUnknown   NodeType = iota
	NodeTypeHunter             // Direct hunter connection
	NodeTypeProcessor          // Processor (aggregates hunters)
)

// ClientConfig holds configuration for remote capture client
type ClientConfig struct {
	// Address of remote node (host:port)
	Address string

	// TLS settings
	TLSEnabled            bool   // Enable TLS encryption
	TLSCAFile             string // Path to CA certificate file
	TLSCertFile           string // Path to client certificate file (for mutual TLS)
	TLSKeyFile            string // Path to client key file (for mutual TLS)
	TLSSkipVerify         bool   // Skip certificate verification (insecure, for testing only)
	TLSServerNameOverride string // Override server name for certificate verification
}

// Client wraps gRPC client for remote packet capture
type Client struct {
	conn       *grpc.ClientConn
	dataClient data.DataServiceClient
	mgmtClient management.ManagementServiceClient
	handler    types.EventHandler
	ctx        context.Context
	cancel     context.CancelFunc
	nodeType   NodeType
	nodeID     string // ID of connected node
	addr       string // Address of connected node

	// Interface mapping: hunterID -> []interfaceName (indexed by interface_index)
	interfacesMu sync.RWMutex
	interfaces   map[string][]string

	// Call aggregation for VoIP monitoring
	callsMu         sync.RWMutex
	calls           map[string]*types.CallInfo  // callID -> call state
	rtpStats        map[string]*rtpQualityStats // callID -> RTP quality tracking
	lastCallUpdate  time.Time
	callUpdateTimer *time.Timer

	// Subscription management for hot-swapping
	streamMu       sync.RWMutex
	streamCancel   context.CancelFunc // Cancel function for current stream
	currentHunters []string           // Current hunter filter
}

// rtpQualityStats tracks RTP quality metrics for a call
type rtpQualityStats struct {
	lastSeqNum    uint16
	lastTimestamp uint32
	totalPackets  int
	lostPackets   int
}

// NewClient creates a new remote capture client (deprecated, use NewClientWithConfig)
func NewClient(addr string, handler types.EventHandler) (*Client, error) {
	return NewClientWithConfig(&ClientConfig{
		Address:    addr,
		TLSEnabled: false,
	}, handler)
}

// NewClientWithConfig creates a new remote capture client with TLS support
func NewClientWithConfig(config *ClientConfig, handler types.EventHandler) (*Client, error) {
	// Dial node (hunter or processor)
	ctx, cancel := context.WithCancel(context.Background())

	// Create custom dialer with TCP keepalive
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// Enable TCP keepalive
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
				if opErr != nil {
					return
				}
				// TCP_KEEPIDLE: 10s
				opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 10)
				if opErr != nil {
					return
				}
				// TCP_KEEPINTVL: 5s
				opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 5)
				if opErr != nil {
					return
				}
				// TCP_KEEPCNT: 3
				opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	// Configure keepalive to survive long network interruptions (e.g., laptop standby)
	// More lenient settings to handle temporary network disruptions
	keepaliveParams := keepalive.ClientParameters{
		Time:                30 * time.Second, // Send ping every 30s (less aggressive)
		Timeout:             20 * time.Second, // Wait 20s for ping ack (tolerate delays)
		PermitWithoutStream: true,             // Send pings even without active streams
	}

	// Build dial options
	opts := []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}),
		grpc.WithKeepaliveParams(keepaliveParams),
	}

	// Configure TLS if enabled
	if config.TLSEnabled {
		tlsCreds, err := buildTLSCredentials(config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(tlsCreds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.DialContext(ctx, config.Address, opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to %s: %w", config.Address, err)
	}

	client := &Client{
		conn:       conn,
		dataClient: data.NewDataServiceClient(conn),
		mgmtClient: management.NewManagementServiceClient(conn),
		handler:    handler,
		ctx:        ctx,
		cancel:     cancel,
		addr:       config.Address,
		interfaces: make(map[string][]string),
		calls:      make(map[string]*types.CallInfo),
		rtpStats:   make(map[string]*rtpQualityStats),
	}

	// Detect node type by checking if GetHunterStatus is available
	client.detectNodeType()

	return client, nil
}

// detectNodeType determines if connected node is a hunter or processor
func (c *Client) detectNodeType() {
	// Try GetHunterStatus RPC - only processors have this
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer cancel()

	_, err := c.mgmtClient.GetHunterStatus(ctx, &management.StatusRequest{})
	if err == nil {
		c.nodeType = NodeTypeProcessor
	} else {
		// If GetHunterStatus fails, it's a hunter
		c.nodeType = NodeTypeHunter
		// For hunters, use the address as node ID
		c.nodeID = c.addr
	}
}

// GetNodeType returns the detected node type
func (c *Client) GetNodeType() NodeType {
	return c.nodeType
}

// GetAddr returns the connection address
func (c *Client) GetAddr() string {
	return c.addr
}

// GetConn returns the gRPC connection for direct RPC calls
func (c *Client) GetConn() *grpc.ClientConn {
	return c.conn
}

// GetTopology fetches the complete downstream topology from this processor
// Returns nil if the processor doesn't support topology queries
func (c *Client) GetTopology(ctx context.Context) (*management.ProcessorNode, error) {
	// Only works for processors
	if c.nodeType == NodeTypeHunter {
		return nil, fmt.Errorf("topology is only available from processor nodes")
	}

	resp, err := c.mgmtClient.GetTopology(ctx, &management.TopologyRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get topology: %w", err)
	}

	return resp.Processor, nil
}

// Close closes the connection
func (c *Client) Close() {
	c.cancel()
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			// Note: logger not imported in this package - error is non-fatal during shutdown
			_ = err // Close error during shutdown is acceptable
		}
	}
}

// buildTLSCredentials creates TLS credentials for gRPC client
func buildTLSCredentials(config *ClientConfig) (credentials.TransportCredentials, error) {
	return tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
		CAFile:             config.TLSCAFile,
		CertFile:           config.TLSCertFile,
		KeyFile:            config.TLSKeyFile,
		SkipVerify:         config.TLSSkipVerify,
		ServerNameOverride: config.TLSServerNameOverride,
	})
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// slicesEqual checks if two string slices are equal
func slicesEqual(a, b []string) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	// Check lengths
	if len(a) != len(b) {
		return false
	}
	// Compare elements
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
