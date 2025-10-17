package remotecapture

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	// Stream health monitoring
	lastPacketTime   time.Time
	healthMu         sync.RWMutex
	healthMonRunning atomic.Bool // Track if health monitor is already running

	// Call aggregation for VoIP monitoring
	callsMu         sync.RWMutex
	calls           map[string]*types.CallInfo  // callID -> call state
	rtpStats        map[string]*rtpQualityStats // callID -> RTP quality tracking
	lastCallUpdate  time.Time
	callUpdateTimer *time.Timer
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

	// Configure keepalive to detect broken connections quickly
	keepaliveParams := keepalive.ClientParameters{
		Time:                10 * time.Second, // Send ping every 10s
		Timeout:             3 * time.Second,  // Wait 3s for ping ack
		PermitWithoutStream: true,             // Send pings even without active streams
	}

	// Build dial options
	opts := []grpc.DialOption{
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
		conn:           conn,
		dataClient:     data.NewDataServiceClient(conn),
		mgmtClient:     management.NewManagementServiceClient(conn),
		handler:        handler,
		ctx:            ctx,
		cancel:         cancel,
		addr:           config.Address,
		interfaces:     make(map[string][]string),
		lastPacketTime: time.Now(),
		calls:          make(map[string]*types.CallInfo),
		rtpStats:       make(map[string]*rtpQualityStats),
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

// StreamPackets starts receiving packet stream from remote node
func (c *Client) StreamPackets() error {
	return c.StreamPacketsWithFilter(nil)
}

// StreamPacketsWithFilter starts receiving packet stream from remote node with hunter filter
func (c *Client) StreamPacketsWithFilter(hunterIDs []string) error {
	// Subscribe to packet stream using the new SubscribePackets RPC
	// ClientId is omitted - processor will auto-generate a unique ID
	req := &data.SubscribeRequest{
		HunterIds:       hunterIDs,        // Filter by specific hunters
		HasHunterFilter: hunterIDs != nil, // Set flag to distinguish nil from []
	}

	stream, err := c.dataClient.SubscribePackets(c.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to subscribe to packets: %w", err)
	}

	// Start health monitor to detect stalled streams (only if not already running)
	if !c.healthMonRunning.Load() {
		c.healthMonRunning.Store(true)
		go c.monitorStreamHealth()
	}

	// Start goroutine to receive packets
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
			case <-c.ctx.Done():
				// Context cancelled, normal shutdown
				return
			default:
				batch, err := stream.Recv()
				if err != nil {
					// Don't report error if context was cancelled (normal shutdown)
					if c.ctx.Err() != nil {
						// Shutdown in progress, exit gracefully
						return
					}
					if c.handler != nil {
						// Notify handler of disconnection
						c.handler.OnDisconnect(c.addr, fmt.Errorf("stream error: %w", err))
					}
					return
				}

				// Update last packet time for health monitoring
				c.healthMu.Lock()
				c.lastPacketTime = time.Now()
				c.healthMu.Unlock()

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

// monitorStreamHealth periodically checks if stream is still receiving data
func (c *Client) monitorStreamHealth() {
	defer c.healthMonRunning.Store(false) // Clear flag when monitor exits

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	const streamTimeout = 60 * time.Second // Alert if no packets for 60 seconds

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.healthMu.RLock()
			lastPacket := c.lastPacketTime
			c.healthMu.RUnlock()

			timeSinceLastPacket := time.Since(lastPacket)

			if timeSinceLastPacket > streamTimeout {
				// Stream may be stalled - notify handler
				if c.ctx.Err() == nil && c.handler != nil {
					c.handler.OnDisconnect(c.addr,
						fmt.Errorf("stream timeout: no packets received for %v", timeSinceLastPacket))
				}
				return
			}
		}
	}
}

// SubscribeHunterStatus subscribes to hunter status updates
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
						c.handler.OnHunterStatus(hunters, "", management.ProcessorStatus_PROCESSOR_HEALTHY) // No processor for direct hunter connection
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

				// Get processor ID and status from stats
				processorID := ""
				processorStatus := management.ProcessorStatus_PROCESSOR_HEALTHY
				if resp.ProcessorStats != nil {
					processorID = resp.ProcessorStats.ProcessorId
					processorStatus = resp.ProcessorStats.Status
				}

				// Send to handler
				if c.handler != nil {
					c.handler.OnHunterStatus(hunters, processorID, processorStatus)
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
		_ = c.conn.Close()
	}
}

// convertToPacketDisplay converts a CapturedPacket to PacketDisplay
func (c *Client) convertToPacketDisplay(pkt *data.CapturedPacket, hunterID string) types.PacketDisplay {
	// Determine link type from packet metadata (safe: link types are small enum values)
	linkType := layers.LinkType(pkt.LinkType) // #nosec G115
	if linkType == 0 {
		// Default to Ethernet if not specified
		linkType = layers.LinkTypeEthernet
	}

	// Parse packet using gopacket with correct link type
	packet := gopacket.NewPacket(pkt.Data, linkType, gopacket.Default)

	// Extract basic info
	srcIP := ""
	dstIP := ""
	srcPort := ""
	dstPort := ""
	protocol := ""
	info := ""

	// Extract IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		protocol = ip.Protocol.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		protocol = ip.NextHeader.String()
	} else {
		// No IP layer - check for ARP or other link-layer protocols
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			srcIP = fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
			dstIP = fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3])
			protocol = "ARP"
			switch arp.Operation {
			case 1:
				info = "Request"
			case 2:
				info = "Reply"
			}
		} else if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			srcIP = eth.SrcMAC.String()
			dstIP = eth.DstMAC.String()
			// Handle EtherType - use hex format for non-standard types
			switch eth.EthernetType {
			case layers.EthernetTypeLLC:
				protocol = "LLC"
				info = "Logical Link Control"
			case layers.EthernetTypeDot1Q:
				protocol = "802.1Q"
				info = "VLAN tag"
			case layers.EthernetTypeCiscoDiscovery:
				protocol = "CDP"
				info = "Cisco Discovery Protocol"
			case layers.EthernetTypeLinkLayerDiscovery:
				protocol = "LLDP"
				info = "Link Layer Discovery Protocol"
			case layers.EthernetTypeEthernetCTP:
				protocol = "EthernetCTP"
				info = "Configuration Test Protocol"
			case 0x888E: // 802.1X (EAP)
				protocol = "802.1X"
				info = "Port-based authentication"
			default:
				// Non-standard EtherType - show hex value clearly
				protocol = fmt.Sprintf("0x%04x", uint16(eth.EthernetType))
				info = "Vendor-specific EtherType"
			}
			// Add broadcast indicator if applicable
			if eth.DstMAC.String() == "ff:ff:ff:ff:ff:ff" {
				if info != "" {
					info = info + " (broadcast)"
				} else {
					info = "Broadcast frame"
				}
			}
		} else if linuxSLL := packet.Layer(layers.LayerTypeLinuxSLL); linuxSLL != nil {
			// Linux cooked capture (interface "any")
			sll, _ := linuxSLL.(*layers.LinuxSLL)
			srcIP = fmt.Sprintf("%s", sll.Addr[:sll.AddrLen])
			protocol = sll.EthernetType.String()
			// For cooked capture, destination is not in the header
		} else {
			// Completely unknown packet type
			protocol = "Unknown"
			// Try to show something useful
			if packet.ErrorLayer() != nil {
				info = fmt.Sprintf("Parse error: %v", packet.ErrorLayer().Error())
			} else if len(pkt.Data) > 0 {
				// Show first few bytes as hex
				maxBytes := 8
				if len(pkt.Data) < maxBytes {
					maxBytes = len(pkt.Data)
				}
				info = fmt.Sprintf("%x", pkt.Data[:maxBytes])
			}
		}
	}

	// Extract transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = fmt.Sprintf("%d", tcp.SrcPort)
		dstPort = fmt.Sprintf("%d", tcp.DstPort)
		protocol = "TCP"
		// Add TCP flags to info
		info = fmt.Sprintf("%s → %s [%s]", srcPort, dstPort, formatTCPFlags(tcp))
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = fmt.Sprintf("%d", udp.SrcPort)
		dstPort = fmt.Sprintf("%d", udp.DstPort)
		protocol = "UDP"
		// Add port info
		info = fmt.Sprintf("%s → %s", srcPort, dstPort)
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		// Handle ICMP separately since it's not a transport layer
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		protocol = "ICMP"
		if icmp != nil {
			info = fmt.Sprintf("Type %d Code %d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
		} else {
			info = "ICMP packet"
		}
	} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		icmp6, _ := icmp6Layer.(*layers.ICMPv6)
		protocol = "ICMPv6"
		if icmp6 != nil {
			info = fmt.Sprintf("Type %d Code %d", icmp6.TypeCode.Type(), icmp6.TypeCode.Code())
		} else {
			info = "ICMPv6 packet"
		}
	} else if igmpLayer := packet.Layer(layers.LayerTypeIGMP); igmpLayer != nil {
		// Handle IGMP (Internet Group Management Protocol)
		igmp, _ := igmpLayer.(*layers.IGMP)
		protocol = "IGMP"
		if igmp != nil {
			info = fmt.Sprintf("Type %d Group %s", igmp.Type, igmp.GroupAddress.String())
		} else {
			info = "IGMP packet"
		}
	}

	// Use pre-computed metadata from processor if available (centralized detection)
	if pkt.Metadata != nil && pkt.Metadata.Protocol != "" {
		protocol = pkt.Metadata.Protocol

		// Use metadata IPs/ports if available (avoid re-parsing packet)
		if pkt.Metadata.SrcIp != "" {
			srcIP = pkt.Metadata.SrcIp
		}
		if pkt.Metadata.DstIp != "" {
			dstIP = pkt.Metadata.DstIp
		}
		if pkt.Metadata.SrcPort > 0 {
			srcPort = fmt.Sprintf("%d", pkt.Metadata.SrcPort)
		}
		if pkt.Metadata.DstPort > 0 {
			dstPort = fmt.Sprintf("%d", pkt.Metadata.DstPort)
		}

		// Use pre-computed info string if available (processor already built it)
		if pkt.Metadata.Info != "" {
			info = pkt.Metadata.Info
		} else {
			// Fallback: extract protocol-specific info from metadata
			switch protocol {
			case "SIP":
				if pkt.Metadata.Sip != nil {
					if pkt.Metadata.Sip.Method != "" {
						info = pkt.Metadata.Sip.Method
					} else if pkt.Metadata.Sip.ResponseCode > 0 {
						info = fmt.Sprintf("%d", pkt.Metadata.Sip.ResponseCode)
					}
				}

			case "RTP":
				if pkt.Metadata.Rtp != nil {
					// Derive codec name from payload type (safe: RTP payload type is 0-127)
					if pkt.Metadata.Rtp.PayloadType > 0 {
						codec := payloadTypeToCodec(uint8(pkt.Metadata.Rtp.PayloadType)) // #nosec G115
						info = codec
					} else {
						info = "RTP stream"
					}
				}
			}
		}
	}

	// Fallback to application layer detection
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		if len(payload) > 0 {
			// DNS detection (port 53 or DNS layer)
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				protocol = "DNS"
				info = "DNS Query/Response"
			} else if (srcPort == "53" || dstPort == "53") && protocol == "UDP" {
				protocol = "DNS"
				info = "DNS Query/Response"
			}
			// Note: Removed overly-broad SIP detection that was showing binary data
			// SIP should be detected via metadata from hunter/processor
		}
	}

	// Parse timestamp
	ts := time.Unix(0, pkt.TimestampNs)

	// Get actual interface name from mapping
	c.interfacesMu.RLock()
	hunterInterfaces, exists := c.interfaces[hunterID]
	c.interfacesMu.RUnlock()

	var ifaceName string
	if exists && int(pkt.InterfaceIndex) < len(hunterInterfaces) {
		// Use actual interface name from hunter registration
		ifaceName = hunterInterfaces[pkt.InterfaceIndex]
	} else {
		// Fallback to interface index if mapping not available yet
		ifaceName = fmt.Sprintf("iface%d", pkt.InterfaceIndex)
	}

	// Build VoIP metadata if present
	var voipData *types.VoIPMetadata
	if pkt.Metadata != nil && (pkt.Metadata.Sip != nil || pkt.Metadata.Rtp != nil) {
		voipData = &types.VoIPMetadata{}

		// SIP metadata
		if pkt.Metadata.Sip != nil {
			voipData.CallID = pkt.Metadata.Sip.CallId
			voipData.Method = pkt.Metadata.Sip.Method
			voipData.Status = int(pkt.Metadata.Sip.ResponseCode)
			voipData.From = pkt.Metadata.Sip.FromUser
			voipData.To = pkt.Metadata.Sip.ToUser
			// ALWAYS mark as SIP if we have SIP metadata from hunter
			// Trust the hunter's analysis even if TUI parsing failed
			protocol = "SIP"
			// Replace info with SIP metadata if it's empty or a parse error
			if info == "" || strings.Contains(info, "Parse error") || strings.Contains(info, "Decode failed") || strings.Contains(info, "Unable to decode") {
				if pkt.Metadata.Sip.Method != "" {
					info = pkt.Metadata.Sip.Method
				} else if pkt.Metadata.Sip.ResponseCode > 0 {
					info = fmt.Sprintf("%d", pkt.Metadata.Sip.ResponseCode)
				}
			}
		}

		// RTP metadata
		if pkt.Metadata.Rtp != nil {
			voipData.IsRTP = true
			voipData.SSRC = pkt.Metadata.Rtp.Ssrc
			voipData.PayloadType = uint8(pkt.Metadata.Rtp.PayloadType) // #nosec G115 - RTP payload type is 7 bits (0-127)
			voipData.SequenceNum = uint16(pkt.Metadata.Rtp.Sequence)   // #nosec G115 - RTP sequence is 16 bits
			voipData.Timestamp = pkt.Metadata.Rtp.Timestamp
			// ALWAYS mark as RTP if we have RTP metadata from hunter
			// Trust the hunter's analysis even if TUI parsing failed
			protocol = "RTP"
			// Update info with codec if not already set
			if info == "" || info == fmt.Sprintf("%s → %s", srcPort, dstPort) || strings.Contains(info, "Parse error") {
				codec := payloadTypeToCodec(voipData.PayloadType)
				info = fmt.Sprintf("SSRC=%d %s", voipData.SSRC, codec)
			}
		}
	}

	return types.PacketDisplay{
		Timestamp: ts,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  protocol,
		Length:    int(pkt.CaptureLength),
		Info:      info,
		RawData:   pkt.Data,
		NodeID:    hunterID,  // Set node ID from batch
		Interface: ifaceName, // Interface where packet was captured
		VoIPData:  voipData,  // VoIP metadata if applicable
		LinkType:  linkType,  // Link layer type
	}
}

// convertToHunterInfo converts ConnectedHunter to HunterInfo
func (c *Client) convertToHunterInfo(h *management.ConnectedHunter) types.HunterInfo {
	// Safe: duration seconds won't overflow int64 nanoseconds (would require ~292 years uptime)
	connectedAt := time.Now().UnixNano() - int64(h.ConnectedDurationSec*1e9) // #nosec G115

	return types.HunterInfo{
		ID:               h.HunterId,
		Hostname:         h.Hostname,
		RemoteAddr:       h.RemoteAddr,
		Status:           h.Status,
		ConnectedAt:      connectedAt,
		LastHeartbeat:    h.LastHeartbeatNs,
		PacketsCaptured:  h.Stats.PacketsCaptured,
		PacketsMatched:   h.Stats.PacketsMatched,
		PacketsForwarded: h.Stats.PacketsForwarded,
		PacketsDropped:   h.Stats.PacketsDropped,
		ActiveFilters:    h.Stats.ActiveFilters,
		Interfaces:       h.Interfaces,
		ProcessorAddr:    c.addr, // Address of processor this client is connected to
	}
}

// calculateMOS computes Mean Opinion Score from packet loss and jitter
// Uses the E-model (ITU-T G.107) simplified calculation
// MOS scale: 1.0 (bad) to 5.0 (excellent)
func calculateMOS(packetLoss, jitter float64) float64 {
	// Clamp inputs to reasonable ranges
	if packetLoss < 0 {
		packetLoss = 0
	}
	if packetLoss > 100 {
		packetLoss = 100
	}
	if jitter < 0 {
		jitter = 0
	}

	// Calculate R-factor (transmission rating factor)
	// R = R0 - Is - Id - Ie + A
	// Where:
	// R0 = 93.2 (base quality)
	// Is = simultaneous impairment (0 for VoIP)
	// Id = delay impairment (from jitter)
	// Ie = equipment impairment (from packet loss and codec)
	// A = advantage factor (0 for VoIP)

	// Delay impairment from jitter
	// Simplified: Id increases with jitter (threshold at 150ms)
	delayImpairment := 0.0
	if jitter > 150 {
		delayImpairment = (jitter - 150) / 10.0
	} else {
		delayImpairment = jitter / 40.0
	}

	// Equipment impairment from packet loss
	// Simplified: Ie = packet_loss_pct * factor
	equipmentImpairment := packetLoss * 2.5

	// Calculate R-factor
	rFactor := 93.2 - delayImpairment - equipmentImpairment

	// Clamp R-factor to valid range (0-100)
	if rFactor < 0 {
		rFactor = 0
	}
	if rFactor > 100 {
		rFactor = 100
	}

	// Convert R-factor to MOS
	// MOS = 1 + 0.035*R + 7*10^-6*R*(R-60)*(100-R)
	var mos float64
	if rFactor < 0 {
		mos = 1.0
	} else if rFactor > 100 {
		mos = 4.5
	} else {
		mos = 1.0 + 0.035*rFactor + 7e-6*rFactor*(rFactor-60)*(100-rFactor)
	}

	// Clamp MOS to valid range (1.0-5.0)
	if mos < 1.0 {
		mos = 1.0
	}
	if mos > 5.0 {
		mos = 5.0
	}

	return mos
}

// payloadTypeToCodec maps RTP payload type to codec name
// Based on IANA RTP Payload Types: https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml
func payloadTypeToCodec(pt uint8) string {
	codecs := map[uint8]string{
		0:   "G.711 µ-law",
		3:   "GSM",
		4:   "G.723",
		5:   "DVI4 8kHz",
		6:   "DVI4 16kHz",
		7:   "LPC",
		8:   "G.711 A-law",
		9:   "G.722",
		10:  "L16 Stereo",
		11:  "L16 Mono",
		12:  "QCELP",
		13:  "Comfort Noise",
		14:  "MPA",
		15:  "G.728",
		16:  "DVI4 11kHz",
		17:  "DVI4 22kHz",
		18:  "G.729",
		25:  "CelB",
		26:  "JPEG",
		28:  "nv",
		31:  "H.261",
		32:  "MPV",
		33:  "MP2T",
		34:  "H.263",
		101: "telephone-event", // DTMF
	}

	if codec, ok := codecs[pt]; ok {
		return codec
	}

	// Dynamic payload types (96-127) require SDP negotiation to determine codec
	if pt >= 96 && pt <= 127 {
		return "Dynamic"
	}

	return "Unknown"
}

// formatTCPFlags returns a string representation of TCP flags
func formatTCPFlags(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "SYN "
	}
	if tcp.ACK {
		flags += "ACK "
	}
	if tcp.FIN {
		flags += "FIN "
	}
	if tcp.RST {
		flags += "RST "
	}
	if tcp.PSH {
		flags += "PSH "
	}
	if tcp.URG {
		flags += "URG "
	}
	if flags == "" {
		return "NONE"
	}
	return flags[:len(flags)-1] // Remove trailing space
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

// updateCallState updates call state from SIP packet metadata
func (c *Client) updateCallState(pkt *data.CapturedPacket, hunterID string) {
	sip := pkt.Metadata.Sip
	if sip == nil || sip.CallId == "" {
		return
	}

	c.callsMu.Lock()
	defer c.callsMu.Unlock()

	call, exists := c.calls[sip.CallId]
	if !exists {
		// Prefer full URIs if available, fallback to username only
		from := sip.FromUri
		if from == "" {
			from = sip.FromUser
		}
		to := sip.ToUri
		if to == "" {
			to = sip.ToUser
		}

		// New call
		call = &types.CallInfo{
			CallID:    sip.CallId,
			From:      from,
			To:        to,
			State:     "NEW",
			StartTime: time.Unix(0, pkt.TimestampNs),
			NodeID:    c.nodeID,
			Hunters:   []string{hunterID},
		}
		c.calls[sip.CallId] = call
	} else {
		// Update existing call
		if !contains(call.Hunters, hunterID) {
			call.Hunters = append(call.Hunters, hunterID)
		}
	}

	// Update state based on SIP method and response code
	call.PacketCount++
	deriveSIPState(call, sip.Method, sip.ResponseCode)
}

// deriveSIPState updates call state based on SIP message
func deriveSIPState(call *types.CallInfo, method string, responseCode uint32) {
	switch method {
	case "INVITE":
		if call.State == "NEW" {
			call.State = "RINGING"
		}
	case "ACK":
		if call.State == "RINGING" {
			call.State = "ACTIVE"
		}
	case "BYE":
		call.State = "ENDED"
		if call.EndTime.IsZero() {
			call.EndTime = time.Now()
		}
	case "CANCEL":
		call.State = "FAILED"
		if call.EndTime.IsZero() {
			call.EndTime = time.Now()
		}
	}

	// Handle response codes
	if responseCode >= 200 && responseCode < 300 {
		// 2xx Success
		if call.State == "RINGING" {
			call.State = "ACTIVE"
		}
	} else if responseCode >= 400 {
		// 4xx/5xx/6xx Error
		call.State = "FAILED"
		if call.EndTime.IsZero() {
			call.EndTime = time.Now()
		}
	}
}

// updateRTPQuality updates RTP quality metrics from packet metadata
func (c *Client) updateRTPQuality(pkt *data.CapturedPacket) {
	rtp := pkt.Metadata.Rtp
	sip := pkt.Metadata.Sip

	// Debug: log entry
	f, _ := os.OpenFile("/tmp/lippycat-rtp-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		fmt.Fprintf(f, "[%s] updateRTPQuality called: has_rtp=%v has_sip=%v call_id=%s\n",
			time.Now().Format("15:04:05"), rtp != nil, sip != nil,
			func() string {
				if sip != nil {
					return sip.CallId
				}
				return ""
			}())
		_ = f.Close() // Debug file, ignore close errors
	}

	if rtp == nil || sip == nil || sip.CallId == "" {
		return
	}

	callID := sip.CallId

	c.callsMu.Lock()
	defer c.callsMu.Unlock()

	// Get or create call (RTP may arrive before SIP in some cases)
	call, exists := c.calls[callID]
	if !exists {
		// RTP packet without prior SIP - shouldn't happen normally but be defensive
		return
	}

	// Get or initialize RTP stats for this call
	stats, exists := c.rtpStats[callID]
	if !exists {
		stats = &rtpQualityStats{
			lastSeqNum:    uint16(rtp.Sequence), // #nosec G115 - RTP sequence is 16 bits
			lastTimestamp: rtp.Timestamp,
			totalPackets:  0,
			lostPackets:   0,
		}
		c.rtpStats[callID] = stats

		// Extract codec from payload type (first RTP packet)
		call.Codec = payloadTypeToCodec(uint8(rtp.PayloadType)) // #nosec G115 - RTP payload type is 7 bits (0-127)

		// Debug: write to file
		f, _ := os.OpenFile("/tmp/lippycat-rtp-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if f != nil {
			fmt.Fprintf(f, "[%s] First RTP packet for call %s: payload_type=%d codec=%s\n",
				time.Now().Format("15:04:05"), callID, rtp.PayloadType, call.Codec)
			_ = f.Close() // Debug file, ignore close errors
		}
	}

	// Detect packet loss from sequence number gaps
	if stats.totalPackets > 0 {
		expectedSeq := stats.lastSeqNum + 1
		actualSeq := uint16(rtp.Sequence) // #nosec G115 - RTP sequence is 16 bits

		// Handle sequence number wraparound (uint16 overflow)
		var gap int
		if actualSeq >= expectedSeq {
			gap = int(actualSeq - expectedSeq)
		} else {
			// Wraparound occurred
			gap = int(65535 - uint32(expectedSeq) + uint32(actualSeq) + 1)
		}

		if gap > 0 {
			// Detect out-of-order or lost packets
			if gap < 1000 { // Sanity check: ignore large gaps (likely restart)
				stats.lostPackets += gap
			}
		}
	}

	stats.lastSeqNum = uint16(rtp.Sequence) // #nosec G115 - RTP sequence is 16 bits
	stats.totalPackets++

	// Calculate packet loss percentage
	if stats.totalPackets > 0 {
		call.PacketLoss = (float64(stats.lostPackets) / float64(stats.totalPackets)) * 100.0
	}

	// Calculate jitter using RFC 3550 algorithm
	if stats.totalPackets > 1 && stats.lastTimestamp != 0 {
		// Calculate inter-arrival jitter
		// J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
		timestampDiff := int64(rtp.Timestamp) - int64(stats.lastTimestamp)
		if timestampDiff < 0 {
			timestampDiff = -timestampDiff
		}

		// Convert to milliseconds (assuming 8kHz clock rate for most codecs)
		timestampDiffMs := float64(timestampDiff) / 8.0

		// Update jitter with smoothing factor (1/16 as per RFC 3550)
		call.Jitter = call.Jitter + (timestampDiffMs-call.Jitter)/16.0
	}

	stats.lastTimestamp = rtp.Timestamp

	// Calculate MOS (Mean Opinion Score) based on packet loss and jitter
	call.MOS = calculateMOS(call.PacketLoss, call.Jitter)
}

// maybeNotifyCallUpdates periodically notifies handler of call state updates
func (c *Client) maybeNotifyCallUpdates() {
	// Throttle updates to max every 500ms
	c.callsMu.RLock()
	lastUpdate := c.lastCallUpdate
	c.callsMu.RUnlock()

	if time.Since(lastUpdate) < 500*time.Millisecond {
		return
	}

	c.callsMu.Lock()
	c.lastCallUpdate = time.Now()

	// Copy calls to slice for notification
	calls := make([]types.CallInfo, 0, len(c.calls))
	for _, call := range c.calls {
		// Calculate duration for active calls
		if call.State == "ACTIVE" && call.EndTime.IsZero() {
			call.Duration = time.Since(call.StartTime)
		} else if !call.EndTime.IsZero() {
			call.Duration = call.EndTime.Sub(call.StartTime)
		}
		calls = append(calls, *call)
	}
	c.callsMu.Unlock()

	// Notify handler
	if c.handler != nil && len(calls) > 0 {
		c.handler.OnCallUpdate(calls)
	}
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
