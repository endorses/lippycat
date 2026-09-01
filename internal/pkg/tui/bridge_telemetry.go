//go:build tui || all

package tui

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ingressTalkerLimit     = 10000
	ingressPublishInterval = 250 * time.Millisecond
)

// IngressTelemetrySnapshot is exact for packets and bytes accepted by the TUI
// bridge. ProtocolCounts intentionally describes inexpensive L3/L4
// classification; application protocols remain attributes of the sampled detail
// feed. Talker maps are bounded and may omit new cardinalities after the limit.
type IngressTelemetrySnapshot struct {
	Packets        int64
	Bytes          int64
	MinPacketSize  int
	MaxPacketSize  int
	ProtocolCounts map[string]int64
	SourceCounts   map[string]int64
	DestCounts     map[string]int64
}

type ingressTelemetryAccumulator struct {
	packets        int64
	bytes          int64
	minPacketSize  int
	maxPacketSize  int
	protocolCounts map[string]int64
	sourceCounts   map[string]int64
	destCounts     map[string]int64
	lastPublished  time.Time
}

func newIngressTelemetryAccumulator(now time.Time) *ingressTelemetryAccumulator {
	return &ingressTelemetryAccumulator{
		minPacketSize:  -1,
		protocolCounts: make(map[string]int64, 16),
		sourceCounts:   make(map[string]int64, ingressTalkerLimit),
		destCounts:     make(map[string]int64, ingressTalkerLimit),
		lastPublished:  now,
	}
}

// observe records a valid envelope without copying payload data or constructing
// a PacketDisplay. It returns false when the envelope cannot be decoded.
func (a *ingressTelemetryAccumulator) observe(env *pipeline.PacketEnvelope) bool {
	if env == nil {
		return false
	}
	pkt := env.Packet()
	if pkt == nil {
		return false
	}

	size := env.OriginalLength
	if size <= 0 {
		size = env.CaptureLength
	}
	if size <= 0 {
		size = len(env.Data)
	}
	a.packets++
	a.bytes += int64(size)
	if a.minPacketSize < 0 || size < a.minPacketSize {
		a.minPacketSize = size
	}
	if size > a.maxPacketSize {
		a.maxPacketSize = size
	}

	protocol, src, dst := ingressClassification(pkt)
	a.protocolCounts[protocol]++
	incrementBounded(a.sourceCounts, src, ingressTalkerLimit)
	incrementBounded(a.destCounts, dst, ingressTalkerLimit)
	return true
}

func (a *ingressTelemetryAccumulator) snapshot(now time.Time, force bool) (IngressTelemetrySnapshot, bool) {
	if !force && now.Sub(a.lastPublished) < ingressPublishInterval {
		return IngressTelemetrySnapshot{}, false
	}
	a.lastPublished = now
	return IngressTelemetrySnapshot{
		Packets: a.packets, Bytes: a.bytes,
		MinPacketSize: a.minPacketSize, MaxPacketSize: a.maxPacketSize,
		ProtocolCounts: cloneCounts(a.protocolCounts),
		SourceCounts:   cloneCounts(a.sourceCounts), DestCounts: cloneCounts(a.destCounts),
	}, true
}

func ingressClassification(pkt gopacket.Packet) (protocol, src, dst string) {
	protocol = "Other L3/L4"
	if network := pkt.NetworkLayer(); network != nil {
		srcEndpoint, dstEndpoint := network.NetworkFlow().Endpoints()
		src, dst = srcEndpoint.String(), dstEndpoint.String()
	}
	switch {
	case pkt.Layer(layers.LayerTypeTCP) != nil:
		protocol = "TCP"
	case pkt.Layer(layers.LayerTypeUDP) != nil:
		protocol = "UDP"
	case pkt.Layer(layers.LayerTypeICMPv4) != nil:
		protocol = "ICMP"
	case pkt.Layer(layers.LayerTypeICMPv6) != nil:
		protocol = "ICMPv6"
	case pkt.Layer(layers.LayerTypeARP) != nil:
		protocol = "ARP"
	}
	return protocol, src, dst
}

func incrementBounded(counts map[string]int64, key string, limit int) {
	if key == "" {
		return
	}
	if _, exists := counts[key]; exists || len(counts) < limit {
		counts[key]++
	}
}

func cloneCounts(counts map[string]int64) map[string]int64 {
	clone := make(map[string]int64, len(counts))
	for key, count := range counts {
		clone[key] = count
	}
	return clone
}

var publishedIngressTelemetry struct {
	sync.RWMutex
	snapshot IngressTelemetrySnapshot
}

func publishIngressTelemetry(snapshot IngressTelemetrySnapshot) {
	publishedIngressTelemetry.Lock()
	publishedIngressTelemetry.snapshot = snapshot
	publishedIngressTelemetry.Unlock()
}

// GetIngressTelemetrySnapshot returns the latest bounded-cadence snapshot.
func GetIngressTelemetrySnapshot() IngressTelemetrySnapshot {
	publishedIngressTelemetry.RLock()
	snapshot := publishedIngressTelemetry.snapshot
	publishedIngressTelemetry.RUnlock()
	snapshot.ProtocolCounts = cloneCounts(snapshot.ProtocolCounts)
	snapshot.SourceCounts = cloneCounts(snapshot.SourceCounts)
	snapshot.DestCounts = cloneCounts(snapshot.DestCounts)
	return snapshot
}

func resetIngressTelemetry() {
	publishIngressTelemetry(IngressTelemetrySnapshot{MinPacketSize: -1})
}
