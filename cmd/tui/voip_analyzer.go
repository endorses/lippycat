//go:build tui || all
// +build tui all

package tui

import (
	"context"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// VoIPAnalyzer handles GPU-accelerated VoIP packet analysis
type VoIPAnalyzer struct {
	gpuAccel      *voip.GPUAccelerator
	config        *voip.GPUConfig
	batchSize     int
	batchTimeout  time.Duration
	packetQueue   chan analyzeRequest
	resultQueue   chan analyzeResult
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	enabled       bool
	program       *tea.Program
}

type analyzeRequest struct {
	packet    gopacket.Packet
	timestamp time.Time
}

type analyzeResult struct {
	display  components.PacketDisplay
	voipData *components.VoIPMetadata
}

// NewVoIPAnalyzer creates a new VoIP analyzer with GPU acceleration
func NewVoIPAnalyzer(config *voip.GPUConfig, program *tea.Program) (*VoIPAnalyzer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	va := &VoIPAnalyzer{
		config:       config,
		batchSize:    100, // Default batch size
		batchTimeout: 10 * time.Millisecond,
		packetQueue:  make(chan analyzeRequest, constants.VoIPAnalyzerQueueBuffer),
		resultQueue:  make(chan analyzeResult, constants.VoIPAnalyzerQueueBuffer),
		ctx:          ctx,
		cancel:       cancel,
		enabled:      config != nil && config.Enabled,
		program:      program,
	}

	// Initialize GPU accelerator if enabled
	if va.enabled {
		gpuAccel, err := voip.NewGPUAccelerator(config)
		if err != nil {
			logger.Warn("Failed to initialize GPU accelerator, falling back to CPU", "error", err)
			va.enabled = false
		} else {
			va.gpuAccel = gpuAccel
		}
	}

	// Start batch processor
	va.wg.Add(1)
	go va.batchProcessor()

	return va, nil
}

// AnalyzePacket queues a packet for VoIP analysis
func (va *VoIPAnalyzer) AnalyzePacket(packet gopacket.Packet, timestamp time.Time) {
	if !va.enabled {
		// CPU fallback - parse immediately
		display := va.parsePacketCPU(packet, timestamp)
		if va.program != nil {
			va.program.Send(PacketMsg{Packet: display})
		}
		return
	}

	// Queue for GPU batch processing
	select {
	case va.packetQueue <- analyzeRequest{packet: packet, timestamp: timestamp}:
	case <-va.ctx.Done():
		return
	default:
		// Queue full - fall back to CPU parsing
		display := va.parsePacketCPU(packet, timestamp)
		if va.program != nil {
			va.program.Send(PacketMsg{Packet: display})
		}
	}
}

// batchProcessor collects packets and processes them in batches using GPU
func (va *VoIPAnalyzer) batchProcessor() {
	defer va.wg.Done()

	batch := make([]analyzeRequest, 0, va.batchSize)
	ticker := time.NewTicker(va.batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-va.ctx.Done():
			// Process remaining batch before exiting
			if len(batch) > 0 {
				va.processBatch(batch)
			}
			return

		case req := <-va.packetQueue:
			batch = append(batch, req)
			if len(batch) >= va.batchSize {
				va.processBatch(batch)
				batch = make([]analyzeRequest, 0, va.batchSize)
				ticker.Reset(va.batchTimeout)
			}

		case <-ticker.C:
			// Timeout - process whatever we have
			if len(batch) > 0 {
				va.processBatch(batch)
				batch = make([]analyzeRequest, 0, va.batchSize)
			}
		}
	}
}

// processBatch processes a batch of packets using GPU or CPU
func (va *VoIPAnalyzer) processBatch(batch []analyzeRequest) {
	if !va.enabled || va.gpuAccel == nil {
		// CPU fallback
		va.processBatchCPU(batch)
		return
	}

	// TODO: Implement GPU batch processing
	// For now, fall back to CPU
	va.processBatchCPU(batch)
}

// processBatchCPU processes a batch using CPU parsing
func (va *VoIPAnalyzer) processBatchCPU(batch []analyzeRequest) {
	displays := make([]components.PacketDisplay, 0, len(batch))

	for _, req := range batch {
		display := va.parsePacketCPU(req.packet, req.timestamp)
		displays = append(displays, display)
	}

	// Send batch to TUI
	if va.program != nil && len(displays) > 0 {
		va.program.Send(PacketBatchMsg{Packets: displays})
	}
}

// parsePacketCPU parses a single packet using CPU (fallback)
func (va *VoIPAnalyzer) parsePacketCPU(packet gopacket.Packet, timestamp time.Time) components.PacketDisplay {
	display := components.PacketDisplay{
		Timestamp: timestamp,
		RawData:   packet.Data(),
		NodeID:    "Local",
	}

	// Extract network layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		display.SrcIP = ip.SrcIP.String()
		display.DstIP = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		display.SrcIP = ip.SrcIP.String()
		display.DstIP = ip.DstIP.String()
	}

	// Extract transport layer and determine protocol
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		display.SrcPort = tcp.SrcPort.String()
		display.DstPort = tcp.DstPort.String()
		display.Protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		display.SrcPort = udp.SrcPort.String()
		display.DstPort = udp.DstPort.String()
		display.Protocol = "UDP"

		// Check if this might be VoIP (SIP/RTP)
		voipData := va.parseVoIPData(packet, udp)
		if voipData != nil {
			display.VoIPData = voipData
			if voipData.IsRTP {
				display.Protocol = "RTP"
				display.Info = voipData.Method // Codec info or other RTP details
			} else {
				display.Protocol = "SIP"
				display.Info = voipData.Method
			}
		}
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		display.Protocol = "ICMP"
	}

	display.Length = len(packet.Data())

	return display
}

// parseVoIPData extracts VoIP metadata from a UDP packet
func (va *VoIPAnalyzer) parseVoIPData(packet gopacket.Packet, udp *layers.UDP) *components.VoIPMetadata {
	// Check for SIP (port 5060 or payload starts with SIP method)
	if udp.SrcPort == 5060 || udp.DstPort == 5060 {
		return va.parseSIPPacket(packet)
	}

	// Check for RTP (common RTP ports 10000-20000)
	srcPort := int(udp.SrcPort)
	dstPort := int(udp.DstPort)
	if (srcPort >= 10000 && srcPort <= 20000) || (dstPort >= 10000 && dstPort <= 20000) {
		return va.parseRTPPacket(packet)
	}

	return nil
}

// parseSIPPacket extracts SIP metadata
func (va *VoIPAnalyzer) parseSIPPacket(packet gopacket.Packet) *components.VoIPMetadata {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return nil
	}

	payload := string(appLayer.Payload())

	// Basic SIP detection
	if !isSIPPayload(payload) {
		return nil
	}

	metadata := &components.VoIPMetadata{
		Headers: make(map[string]string),
		IsRTP:   false,
	}

	// Parse SIP method (first line)
	lines := splitLines(payload)
	if len(lines) > 0 {
		metadata.Method = extractSIPMethod(lines[0])
	}

	// Parse headers
	for _, line := range lines[1:] {
		if line == "" {
			break // End of headers
		}
		key, value := parseSIPHeader(line)
		if key != "" {
			metadata.Headers[key] = value

			// Extract common fields
			switch key {
			case "From":
				metadata.From = value
				metadata.User = extractUserFromURI(value)
			case "To":
				metadata.To = value
			case "Call-ID":
				metadata.CallID = value
			}
		}
	}

	return metadata
}

// parseRTPPacket extracts RTP metadata
func (va *VoIPAnalyzer) parseRTPPacket(packet gopacket.Packet) *components.VoIPMetadata {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil || len(appLayer.Payload()) < 12 {
		return nil
	}

	payload := appLayer.Payload()

	// RTP header check (version should be 2)
	version := (payload[0] >> 6) & 0x03
	if version != 2 {
		return nil
	}

	metadata := &components.VoIPMetadata{
		IsRTP:   true,
		Headers: make(map[string]string),
	}

	// Extract SSRC (bytes 8-11)
	metadata.SSRC = uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])

	// Extract sequence number (bytes 2-3)
	metadata.SeqNumber = uint16(payload[2])<<8 | uint16(payload[3])

	// Extract payload type (byte 1, lower 7 bits)
	payloadType := payload[1] & 0x7F
	metadata.Codec = rtpPayloadTypeToCodec(payloadType)
	metadata.Method = metadata.Codec // Store codec in Method field for display

	return metadata
}

// Helper functions

func isSIPPayload(payload string) bool {
	methods := []string{"INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "SIP/2.0"}
	for _, method := range methods {
		if len(payload) >= len(method) && payload[:len(method)] == method {
			return true
		}
	}
	return false
}

// Helper functions are now defined in bridge.go to avoid duplication

// Close shuts down the analyzer
func (va *VoIPAnalyzer) Close() {
	va.cancel()
	va.wg.Wait()

	if va.gpuAccel != nil {
		// GPU cleanup would go here
	}

	close(va.packetQueue)
	close(va.resultQueue)
}
