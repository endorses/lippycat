package remotecapture

import (
	"context"
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components"
)

// NodeType represents the type of remote node
type NodeType int

const (
	NodeTypeUnknown NodeType = iota
	NodeTypeHunter           // Direct hunter connection
	NodeTypeProcessor        // Processor (aggregates hunters)
)

// Client wraps gRPC client for remote packet capture
type Client struct {
	conn       *grpc.ClientConn
	dataClient data.DataServiceClient
	mgmtClient management.ManagementServiceClient
	program    *tea.Program
	ctx        context.Context
	cancel     context.CancelFunc
	nodeType   NodeType
	nodeID     string // ID of connected node
	addr       string // Address of connected node

	// Interface mapping: hunterID -> []interfaceName (indexed by interface_index)
	interfacesMu sync.RWMutex
	interfaces   map[string][]string
}

// PacketMsg is sent to TUI when a single packet is received
// This must match the type in cmd/tui/model.go
type PacketMsg struct {
	Packet components.PacketDisplay
}

// PacketBatchMsg is sent to TUI when a batch of packets is received
// This must match the type in cmd/tui/bridge.go
type PacketBatchMsg struct {
	Packets []components.PacketDisplay
}

// HunterStatusMsg is sent to TUI with hunter status updates
// This must match the type in cmd/tui/model.go
type HunterStatusMsg struct {
	Hunters []components.HunterInfo
}

// NewClient creates a new remote capture client
func NewClient(addr string, program *tea.Program) (*Client, error) {
	// Dial node (hunter or processor)
	ctx, cancel := context.WithCancel(context.Background())

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	client := &Client{
		conn:       conn,
		dataClient: data.NewDataServiceClient(conn),
		mgmtClient: management.NewManagementServiceClient(conn),
		program:    program,
		ctx:        ctx,
		cancel:     cancel,
		addr:       addr,
		interfaces: make(map[string][]string),
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

// StreamPackets starts receiving packet stream from remote node
func (c *Client) StreamPackets() error {
	// Subscribe to packet stream using the new SubscribePackets RPC
	// ClientId is omitted - processor will auto-generate a unique ID
	req := &data.SubscribeRequest{}

	stream, err := c.dataClient.SubscribePackets(c.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to subscribe to packets: %w", err)
	}

	// Start goroutine to receive packets
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				batch, err := stream.Recv()
				if err != nil {
					// Connection lost or stream ended
					return
				}

				// Convert entire batch to PacketDisplay and send as single message to TUI
				// This reduces Bubbletea Update() calls by ~100x
				if c.program != nil && len(batch.Packets) > 0 {
					displays := make([]components.PacketDisplay, 0, len(batch.Packets))
					for _, pkt := range batch.Packets {
						display := c.convertToPacketDisplay(pkt, batch.HunterId)
						displays = append(displays, display)
					}
					// Send entire batch as PacketBatchMsg (same as local capture)
					c.program.Send(PacketBatchMsg{Packets: displays})
				}
			}
		}
	}()

	return nil
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
					hunters := []components.HunterInfo{
						{
							ID:            c.nodeID,
							Hostname:      c.addr,
							RemoteAddr:    c.addr,
							Status:        management.HunterStatus_STATUS_HEALTHY,
							ProcessorAddr: "Direct", // Direct hunter connection (no processor)
							// Stats will be inferred from packet stream
						},
					}
					if c.program != nil {
						c.program.Send(HunterStatusMsg{Hunters: hunters})
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
					continue
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
				hunters := make([]components.HunterInfo, len(resp.Hunters))
				for i, h := range resp.Hunters {
					hunters[i] = c.convertToHunterInfo(h)
				}

				// Send to TUI
				if c.program != nil {
					c.program.Send(HunterStatusMsg{Hunters: hunters})
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
		c.conn.Close()
	}
}

// convertToPacketDisplay converts a CapturedPacket to PacketDisplay
func (c *Client) convertToPacketDisplay(pkt *data.CapturedPacket, hunterID string) components.PacketDisplay {
	// Determine link type from packet metadata
	linkType := layers.LinkType(pkt.LinkType)
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
			protocol = eth.EthernetType.String()
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
		}
	} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		icmp6, _ := icmp6Layer.(*layers.ICMPv6)
		protocol = "ICMPv6"
		if icmp6 != nil {
			info = fmt.Sprintf("Type %d Code %d", icmp6.TypeCode.Type(), icmp6.TypeCode.Code())
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
					// Derive codec name from payload type
					if pkt.Metadata.Rtp.PayloadType > 0 {
						codec := payloadTypeToCodec(uint8(pkt.Metadata.Rtp.PayloadType))
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

	return components.PacketDisplay{
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
	}
}

// convertToHunterInfo converts ConnectedHunter to HunterInfo
func (c *Client) convertToHunterInfo(h *management.ConnectedHunter) components.HunterInfo {
	connectedAt := time.Now().UnixNano() - int64(h.ConnectedDurationSec*1e9)

	return components.HunterInfo{
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

// payloadTypeToCodec maps RTP payload type to codec name
func payloadTypeToCodec(pt uint8) string {
	codecs := map[uint8]string{
		0:  "G.711 µ-law",
		8:  "G.711 A-law",
		9:  "G.722",
		18: "G.729",
		97: "Dynamic",
		98: "Dynamic",
		99: "Dynamic",
	}
	if codec, ok := codecs[pt]; ok {
		return codec
	}
	return fmt.Sprintf("PT %d", pt)
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

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
