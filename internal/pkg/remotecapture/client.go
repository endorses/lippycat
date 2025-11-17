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

// StreamPackets starts receiving packet stream from remote node
func (c *Client) StreamPackets() error {
	return c.StreamPacketsWithFilter(nil)
}

// StreamPacketsWithFilter starts receiving packet stream from remote node with hunter filter
func (c *Client) StreamPacketsWithFilter(hunterIDs []string) error {
	// Cancel any existing stream before starting a new one
	c.streamMu.Lock()
	if c.streamCancel != nil {
		c.streamCancel()
	}

	// Create a new context for this stream
	streamCtx, streamCancel := context.WithCancel(c.ctx)
	c.streamCancel = streamCancel
	c.currentHunters = hunterIDs
	c.streamMu.Unlock()

	// Subscribe to packet stream using the new SubscribePackets RPC
	// ClientId is omitted - processor will auto-generate a unique ID
	req := &data.SubscribeRequest{
		HunterIds:       hunterIDs,        // Filter by specific hunters
		HasHunterFilter: hunterIDs != nil, // Set flag to distinguish nil from []
	}

	stream, err := c.dataClient.SubscribePackets(streamCtx, req)
	if err != nil {
		return fmt.Errorf("failed to subscribe to packets: %w", err)
	}

	// Start goroutine to receive packets
	// Note: gRPC keepalive (30s ping + 20s timeout) detects dead connections
	// No additional health monitoring needed
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Notify handler of disconnection after panic
				if c.handler != nil {
					c.handler.OnDisconnect(c.addr, fmt.Errorf("panic in packet receiver: %v", r))
				}
			}
		}()

		for {
			select {
			case <-streamCtx.Done():
				// Stream context cancelled (hot-swap or shutdown)
				return
			case <-c.ctx.Done():
				// Client context cancelled, normal shutdown
				return
			default:
				batch, err := stream.Recv()
				if err != nil {
					// Don't report error if context was cancelled (normal shutdown or hot-swap)
					if streamCtx.Err() != nil || c.ctx.Err() != nil {
						// Shutdown or hot-swap in progress, exit gracefully
						return
					}
					if c.handler != nil {
						// Notify handler of disconnection
						c.handler.OnDisconnect(c.addr, fmt.Errorf("stream error: %w", err))
					}
					return
				}

				// Convert entire batch to PacketDisplay and send to handler
				if c.handler != nil && len(batch.Packets) > 0 {
					displays := make([]types.PacketDisplay, 0, len(batch.Packets))
					for _, pkt := range batch.Packets {
						display := c.convertToPacketDisplay(pkt, batch.HunterId)
						displays = append(displays, display)

						// Update call state from VoIP metadata
						if pkt.Metadata != nil {
							if pkt.Metadata.Sip != nil {
								c.updateCallState(pkt, batch.HunterId)
							}
							// Update RTP quality metrics
							if pkt.Metadata.Rtp != nil {
								c.updateRTPQuality(pkt)
							}
						}
					}
					// Send entire batch to handler
					c.handler.OnPacketBatch(displays)

					// Periodically notify handler of call updates
					c.maybeNotifyCallUpdates()
				}
			}
		}
	}()

	return nil
}

// UpdateSubscription hot-swaps the hunter subscription without reconnecting
// This enables seamless subscription changes with zero packet loss
func (c *Client) UpdateSubscription(hunterIDs []string) error {
	c.streamMu.RLock()
	// Check if subscription is already the same
	if slicesEqual(c.currentHunters, hunterIDs) {
		c.streamMu.RUnlock()
		return nil // No change needed
	}
	c.streamMu.RUnlock()

	// Start new subscription (this will cancel the old stream automatically)
	return c.StreamPacketsWithFilter(hunterIDs)
}

// SubscribeHunterStatus subscribes to hunter status updates
// SubscribeTopology subscribes to real-time topology updates from a processor
func (c *Client) SubscribeTopology() error {
	// Only works for processors
	if c.nodeType == NodeTypeHunter {
		return fmt.Errorf("topology subscription is only available from processor nodes")
	}

	// Create subscription request
	req := &management.TopologySubscribeRequest{}

	// Start topology stream
	stream, err := c.mgmtClient.SubscribeTopology(c.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to subscribe to topology: %w", err)
	}

	// Start goroutine to receive topology updates
	go func() {
		for {
			update, err := stream.Recv()
			if err != nil {
				// Don't report error if context was cancelled (normal shutdown)
				if c.ctx.Err() == nil && c.handler != nil {
					// Notify handler of disconnection
					c.handler.OnDisconnect(c.addr, fmt.Errorf("topology stream error: %w", err))
				}
				return
			}

			// Send topology update to handler
			if c.handler != nil {
				c.handler.OnTopologyUpdate(update, c.addr)
			}
		}
	}()

	return nil
}

func (c *Client) SubscribeHunterStatus() error {
	// Only works for processors - hunters don't have GetHunterStatus
	if c.nodeType == NodeTypeHunter {
		// For direct hunter connection, create a single HunterInfo entry
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-c.ctx.Done():
					return
				case <-ticker.C:
					// Create hunter info for this direct connection
					hunters := []types.HunterInfo{
						{
							ID:            c.nodeID,
							Hostname:      c.addr,
							RemoteAddr:    c.addr,
							Status:        management.HunterStatus_STATUS_HEALTHY,
							ProcessorAddr: "Direct", // Direct hunter connection (no processor)
							// Stats will be inferred from packet stream
						},
					}
					if c.handler != nil {
						// Direct hunter: no processor ID or upstream
						c.handler.OnHunterStatus(hunters, "", management.ProcessorStatus_PROCESSOR_HEALTHY, c.addr, "")
					}
				}
			}
		}()
		return nil
	}

	// For processors, poll GetHunterStatus
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				resp, err := c.mgmtClient.GetHunterStatus(c.ctx, &management.StatusRequest{})
				if err != nil {
					// Don't report error if context was cancelled (normal shutdown)
					if c.ctx.Err() == nil && c.handler != nil {
						// Notify handler of disconnection
						c.handler.OnDisconnect(c.addr, fmt.Errorf("hunter status error: %w", err))
					}
					return
				}

				// Update interface mapping
				c.interfacesMu.Lock()
				for _, h := range resp.Hunters {
					if len(h.Interfaces) > 0 {
						c.interfaces[h.HunterId] = h.Interfaces
					}
				}
				c.interfacesMu.Unlock()

				// Convert to HunterInfo list
				hunters := make([]types.HunterInfo, len(resp.Hunters))
				for i, h := range resp.Hunters {
					hunters[i] = c.convertToHunterInfo(h)
				}

				// Get processor ID, status, and upstream from stats
				processorID := ""
				processorStatus := management.ProcessorStatus_PROCESSOR_HEALTHY
				upstreamProcessor := ""
				if resp.ProcessorStats != nil {
					processorID = resp.ProcessorStats.ProcessorId
					processorStatus = resp.ProcessorStats.Status
					upstreamProcessor = resp.ProcessorStats.UpstreamProcessor
				}

				// Send to handler with processor address and upstream info
				if c.handler != nil {
					c.handler.OnHunterStatus(hunters, processorID, processorStatus, c.addr, upstreamProcessor)
				}
			}
		}
	}()

	return nil
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

// SubscribeCorrelatedCalls subscribes to correlated call updates from processor
func (c *Client) SubscribeCorrelatedCalls() error {
	// Only works for processors
	if c.nodeType == NodeTypeHunter {
		return fmt.Errorf("correlated calls are only available from processor nodes")
	}

	go func() {
		// Subscribe to correlated calls stream
		stream, err := c.dataClient.SubscribeCorrelatedCalls(c.ctx, &data.SubscribeRequest{})
		if err != nil {
			if c.handler != nil {
				c.handler.OnDisconnect(c.addr, fmt.Errorf("failed to subscribe to correlated calls: %w", err))
			}
			return
		}

		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				update, err := stream.Recv()
				if err != nil {
					if c.ctx.Err() == nil {
						if c.handler != nil {
							c.handler.OnDisconnect(c.addr, fmt.Errorf("correlated calls stream error: %w", err))
						}
					}
					return
				}

				// Convert protobuf to types.CorrelatedCallInfo
				correlatedCall := types.CorrelatedCallInfo{
					CorrelationID: update.CorrelationId,
					TagPair:       [2]string{update.TagPair[0], update.TagPair[1]},
					FromUser:      update.FromUser,
					ToUser:        update.ToUser,
					StartTime:     time.Unix(0, update.StartTimeNs),
					LastSeen:      time.Unix(0, update.LastSeenNs),
					State:         update.State,
				}

				// Convert legs
				correlatedCall.Legs = make([]types.CallLegInfo, len(update.Legs))
				for i, leg := range update.Legs {
					correlatedCall.Legs[i] = types.CallLegInfo{
						CallID:       leg.CallId,
						HunterID:     leg.HunterId,
						SrcIP:        leg.SrcIp,
						DstIP:        leg.DstIp,
						Method:       leg.Method,
						ResponseCode: leg.ResponseCode,
						PacketCount:  int(leg.PacketCount),
						StartTime:    time.Unix(0, leg.StartTimeNs),
						LastSeen:     time.Unix(0, leg.LastSeenNs),
					}
				}

				// Notify handler
				if c.handler != nil {
					c.handler.OnCorrelatedCallUpdate([]types.CorrelatedCallInfo{correlatedCall})
				}
			}
		}
	}()

	return nil
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
