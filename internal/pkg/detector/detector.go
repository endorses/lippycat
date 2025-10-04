package detector

import (
	"context"
	"fmt"
	"hash/fnv"
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

// NewDetector is an alias for New() for compatibility
func NewDetector() *Detector {
	return New()
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

// GetSignatures returns all registered signatures
func (d *Detector) GetSignatures() []signatures.Signature {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Return a copy to prevent external modification
	sigs := make([]signatures.Signature, len(d.signatures))
	copy(sigs, d.signatures)
	return sigs
}

// Detect performs protocol detection on a packet
func (d *Detector) Detect(packet gopacket.Packet) *signatures.DetectionResult {
	ctx := d.buildContext(packet)

	// Check cache only for flow/session protocols, not for single-packet protocols
	// This optimization skips cache for DNS, HTTP GET, etc.
	if cached := d.cache.Get(ctx.FlowID); cached != nil {
		// Only use cache if it was explicitly requested for this protocol
		if cached.CacheStrategy != signatures.CacheNever {
			return cached
		}
	}

	d.mu.RLock()
	sigs := d.signatures
	d.mu.RUnlock()

	// Fast path: Check port-based hints first for well-known ports
	// This avoids checking all signatures when we have a strong hint
	if hint := d.getPortHint(ctx.DstPort); hint != nil {
		if result := hint.Detect(ctx); result != nil && result.Confidence >= signatures.ConfidenceHigh {
			d.cacheAndUpdateFlow(ctx, result)
			return result
		}
	}
	if hint := d.getPortHint(ctx.SrcPort); hint != nil {
		if result := hint.Detect(ctx); result != nil && result.Confidence >= signatures.ConfidenceHigh {
			d.cacheAndUpdateFlow(ctx, result)
			return result
		}
	}

	// Fallback: Try each signature in priority order
	for _, sig := range sigs {
		result := sig.Detect(ctx)
		if result != nil {
			d.cacheAndUpdateFlow(ctx, result)
			return result
		}
	}

	// No protocol detected
	return &signatures.DetectionResult{
		Protocol:      "unknown",
		Confidence:    0.0,
		Metadata:      make(map[string]interface{}),
		ShouldCache:   false,
		CacheStrategy: signatures.CacheNever,
	}
}

// cacheAndUpdateFlow handles caching and flow updates
func (d *Detector) cacheAndUpdateFlow(ctx *signatures.DetectionContext, result *signatures.DetectionResult) {
	// Only cache based on strategy
	switch result.CacheStrategy {
	case signatures.CacheFlow, signatures.CacheSession:
		d.cache.Set(ctx.FlowID, result)
	}

	// Update flow context
	if ctx.Flow != nil {
		ctx.Flow.LastSeen = time.Now()
		if !contains(ctx.Flow.Protocols, result.Protocol) {
			ctx.Flow.Protocols = append(ctx.Flow.Protocols, result.Protocol)
		}
	}
}

// getPortHint returns a signature hint based on well-known port
func (d *Detector) getPortHint(port uint16) signatures.Signature {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Map of well-known ports to signature indices (built at registration)
	// For now, linear search through signatures checking their typical ports
	for _, sig := range d.signatures {
		switch sig.Name() {
		case "DNS Detector":
			if port == 53 {
				return sig
			}
		case "HTTP Detector":
			if port == 80 || port == 8080 {
				return sig
			}
		case "TLS/SSL Detector":
			if port == 443 || port == 8443 {
				return sig
			}
		case "SSH Detector":
			if port == 22 {
				return sig
			}
		case "gRPC/HTTP2 Detector":
			if port == 50051 {
				return sig
			}
		}
	}
	return nil
}

// isWellKnownPort checks if a port is a well-known port where protocols
// typically establish after transport-layer handshake (e.g., HTTP, HTTPS, SSH)
func isWellKnownPort(port uint16) bool {
	wellKnownPorts := map[uint16]bool{
		80:    true, // HTTP
		443:   true, // HTTPS
		8080:  true, // HTTP alternate
		8443:  true, // HTTPS alternate
		22:    true, // SSH
		21:    true, // FTP
		25:    true, // SMTP
		110:   true, // POP3
		143:   true, // IMAP
		3306:  true, // MySQL
		5432:  true, // PostgreSQL
		6379:  true, // Redis
		27017: true, // MongoDB
	}
	return wellKnownPorts[port]
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
func (d *Detector) BuildContext(packet gopacket.Packet) *signatures.DetectionContext {
	return d.buildContext(packet)
}

func (d *Detector) buildContext(packet gopacket.Packet) *signatures.DetectionContext {
	ctx := &signatures.DetectionContext{
		Packet:    packet,
		Transport: "unknown",
		SrcIP:     "unknown",
		DstIP:     "unknown",
		Context:   context.Background(),
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

	// Check for link-layer protocols first (ARP, etc.)
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		ctx.Payload = arpLayer.LayerContents()
	} else if failLayer := packet.Layer(gopacket.LayerTypeDecodeFailure); failLayer != nil {
		// Handle Frame Relay and other encapsulations that gopacket can't decode
		// Look for ARP EtherType (0x0806) and extract ARP data after it
		failData := failLayer.LayerContents()
		for i := 0; i < len(failData)-10; i++ {
			// Check for ARP EtherType
			if failData[i] == 0x08 && failData[i+1] == 0x06 {
				// ARP data starts after EtherType (2 bytes)
				arpStart := i + 2
				if arpStart+8 <= len(failData) {
					// Validate it looks like ARP (reasonable hlen, plen, op)
					hlen := failData[arpStart+4]
					plen := failData[arpStart+5]
					if hlen > 0 && hlen < 20 && plen == 4 {
						ctx.Payload = failData[arpStart:]
						break
					}
				}
			}
		}
	}

	// Check for network-layer protocols (ICMP, etc.)
	if len(ctx.Payload) == 0 {
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			ctx.Payload = icmpLayer.LayerContents()
		} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
			ctx.Payload = icmpLayer.LayerContents()
		}
	}

	// Extract application layer payload
	if len(ctx.Payload) == 0 {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			ctx.Payload = appLayer.Payload()
		}
	}

	// If payload is empty and we have a transport layer, try getting payload from there
	// This handles cases where gopacket's protocol parsers consume the payload
	if len(ctx.Payload) == 0 {
		if transLayer := packet.TransportLayer(); transLayer != nil {
			ctx.Payload = transLayer.LayerPayload()
		}
	}

	// Generate flow ID
	ctx.FlowID = generateFlowID(ctx.SrcIP, ctx.DstIP, ctx.SrcPort, ctx.DstPort, ctx.Transport)

	// Get or create flow context
	ctx.Flow = d.flows.GetOrCreate(ctx.FlowID)

	return ctx
}

// generateFlowID creates a deterministic numeric flow ID from connection 5-tuple
// Uses FNV-1a hash for fast, collision-resistant hashing without string allocations
func generateFlowID(srcIP, dstIP string, srcPort, dstPort uint16, transport string) string {
	h := fnv.New64a()

	// Normalize direction (sort IPs and ports) for bidirectional flow matching
	ip1, ip2, port1, port2 := srcIP, dstIP, srcPort, dstPort
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		ip1, ip2, port1, port2 = dstIP, srcIP, dstPort, srcPort
	}

	// Write to hash (no string concatenation allocations)
	h.Write([]byte(ip1))
	h.Write([]byte{':'})
	h.Write([]byte(ip2))
	h.Write([]byte{':'})

	// Write ports as bytes
	h.Write([]byte{byte(port1 >> 8), byte(port1)})
	h.Write([]byte{':'})
	h.Write([]byte{byte(port2 >> 8), byte(port2)})
	h.Write([]byte{':'})
	h.Write([]byte(transport))

	// Return as string representation of hash (still need string for map key)
	return fmt.Sprintf("%x", h.Sum64())
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
