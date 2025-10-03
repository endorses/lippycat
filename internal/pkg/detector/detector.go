package detector

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Detector is the central protocol detection service
type Detector struct {
	signatures []signatures.Signature
	cache      *DetectionCache
	flows      *FlowTracker
	mu         sync.RWMutex
}

// New creates a new protocol detector
func New() *Detector {
	return &Detector{
		signatures: make([]signatures.Signature, 0),
		cache:      NewDetectionCache(5 * time.Minute),
		flows:      NewFlowTracker(10 * time.Minute),
	}
}

// RegisterSignature registers a new protocol signature
func (d *Detector) RegisterSignature(sig signatures.Signature) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.signatures = append(d.signatures, sig)

	// Sort signatures by priority (descending)
	sort.Slice(d.signatures, func(i, j int) bool {
		return d.signatures[i].Priority() > d.signatures[j].Priority()
	})

	logger.Debug("Registered protocol signature",
		"name", sig.Name(),
		"protocols", sig.Protocols(),
		"priority", sig.Priority(),
		"layer", sig.Layer())
}

// Detect performs protocol detection on a packet
func (d *Detector) Detect(packet gopacket.Packet) *signatures.DetectionResult {
	ctx := d.buildContext(packet)

	// Check cache first
	if cached := d.cache.Get(ctx.FlowID); cached != nil {
		return cached
	}

	// Try each signature in priority order
	d.mu.RLock()
	sigs := d.signatures
	d.mu.RUnlock()

	for _, sig := range sigs {
		result := sig.Detect(ctx)
		if result != nil {
			// Cache the result if requested
			if result.ShouldCache {
				d.cache.Set(ctx.FlowID, result)
			}

			// Update flow context
			if ctx.Flow != nil {
				ctx.Flow.LastSeen = time.Now()
				if !contains(ctx.Flow.Protocols, result.Protocol) {
					ctx.Flow.Protocols = append(ctx.Flow.Protocols, result.Protocol)
				}
			}

			return result
		}
	}

	// No protocol detected - cache negative result
	unknownResult := &signatures.DetectionResult{
		Protocol:    "unknown",
		Confidence:  0.0,
		Metadata:    make(map[string]interface{}),
		ShouldCache: true,
	}
	d.cache.Set(ctx.FlowID, unknownResult)

	return unknownResult
}

// DetectWithoutCache performs detection without using or updating cache
func (d *Detector) DetectWithoutCache(packet gopacket.Packet) *signatures.DetectionResult {
	ctx := d.buildContext(packet)

	d.mu.RLock()
	sigs := d.signatures
	d.mu.RUnlock()

	for _, sig := range sigs {
		result := sig.Detect(ctx)
		if result != nil {
			return result
		}
	}

	return &signatures.DetectionResult{
		Protocol:    "unknown",
		Confidence:  0.0,
		Metadata:    make(map[string]interface{}),
		ShouldCache: false,
	}
}

// buildContext creates a detection context from a packet
func (d *Detector) buildContext(packet gopacket.Packet) *signatures.DetectionContext {
	ctx := &signatures.DetectionContext{
		Packet:    packet,
		Transport: "unknown",
		SrcIP:     "unknown",
		DstIP:     "unknown",
	}

	// Extract network layer info
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		switch net := netLayer.(type) {
		case *layers.IPv4:
			ctx.SrcIP = net.SrcIP.String()
			ctx.DstIP = net.DstIP.String()
		case *layers.IPv6:
			ctx.SrcIP = net.SrcIP.String()
			ctx.DstIP = net.DstIP.String()
		}
	}

	// Extract transport layer info
	if transLayer := packet.TransportLayer(); transLayer != nil {
		switch trans := transLayer.(type) {
		case *layers.TCP:
			ctx.Transport = "TCP"
			ctx.SrcPort = uint16(trans.SrcPort)
			ctx.DstPort = uint16(trans.DstPort)
		case *layers.UDP:
			ctx.Transport = "UDP"
			ctx.SrcPort = uint16(trans.SrcPort)
			ctx.DstPort = uint16(trans.DstPort)
		case *layers.SCTP:
			ctx.Transport = "SCTP"
			ctx.SrcPort = uint16(trans.SrcPort)
			ctx.DstPort = uint16(trans.DstPort)
		}
	}

	// Extract application layer payload
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		ctx.Payload = appLayer.Payload()
	} else if transLayer := packet.TransportLayer(); transLayer != nil {
		// If no application layer, get payload from transport layer
		ctx.Payload = transLayer.LayerPayload()
	}

	// Generate flow ID
	ctx.FlowID = generateFlowID(ctx.SrcIP, ctx.DstIP, ctx.SrcPort, ctx.DstPort, ctx.Transport)

	// Get or create flow context
	ctx.Flow = d.flows.GetOrCreate(ctx.FlowID)

	return ctx
}

// generateFlowID creates a deterministic flow ID from connection 5-tuple
func generateFlowID(srcIP, dstIP string, srcPort, dstPort uint16, transport string) string {
	// Normalize direction (sort IPs and ports)
	ip1, ip2, port1, port2 := srcIP, dstIP, srcPort, dstPort
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		ip1, ip2, port1, port2 = dstIP, srcIP, dstPort, srcPort
	}

	return fmt.Sprintf("%s:%s:%d:%d:%s", ip1, ip2, port1, port2, transport)
}

// GetStats returns detector statistics
func (d *Detector) GetStats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"signatures_registered": len(d.signatures),
		"cache_size":            d.cache.Size(),
		"active_flows":          d.flows.Size(),
	}
}

// ClearCache clears the detection cache
func (d *Detector) ClearCache() {
	d.cache.Clear()
}

// ClearFlows clears flow tracking data
func (d *Detector) ClearFlows() {
	d.flows.Clear()
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
