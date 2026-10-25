package offline

import (
	"context"
	"errors"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// Each revision has its own directory and one lease on the original backing
// owner. Dataset/query/detail pins retain that revision's existing lock. The
// final lease closes the registry; a failed close remains owned for retries.
type compactBackingLease struct {
	mu       sync.Mutex
	registry *BackingRegistry
	released bool
	final    bool
}

func (r *BackingRegistry) retainCompact() (*compactBackingLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.failure != nil {
		return nil, errors.Join(errors.New("offline backing owner unavailable"), r.failure)
	}
	r.compactOwners++
	return &compactBackingLease{registry: r}, nil
}

func (l *compactBackingLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.released {
		l.registry.mu.Lock()
		l.registry.compactOwners--
		l.final = l.registry.compactOwners == 0
		l.registry.mu.Unlock()
		l.released = true
	}
	if l.final {
		return l.registry.Close()
	}
	return nil
}

func basePacket(packet types.PacketDisplay) types.PacketDisplay {
	packet.Protocol, packet.Info = "", ""
	packet.VoIPData, packet.DNSData, packet.EmailData = nil, nil, nil
	packet.TLSData, packet.HTTPData, packet.RADIUSData = nil, nil, nil
	return packet
}

// NewCompactBaseBuilder publishes normalized fields and effective bytes only.
// Its detail decoder cannot run an analyzer or synthesize application metadata.
// As with NewCompactBuilder, registry ownership transfers only on success.
// A non-nil builder with an error retains failed metadata cleanup for Close.
func (s *Storage) NewCompactBaseBuilder(g DatasetGeneration, sources []SourcePosition, registry *BackingRegistry) (*Builder, error) {
	return s.newCompactBuilder(g, sources, registry, func(ctx context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
		packet := basePacket(summary.DisplayFields())
		packet.RawData = raw
		return packet, ctx.Err()
	}, BaseRevision)
}

// NewCompactRevisionBuilder constructs an independent completed metadata
// dataset with stable packet positions and the base's validated byte handles.
// It retains its own backing lease before the base may close. Failure leaves
// base ownership unchanged. Successful Finish requires every base packet.
// Retain any non-nil builder returned with an error for metadata cleanup retries.
func (s *Storage) NewCompactRevisionBuilder(base Dataset, revision AnalysisRevision, decode StatelessDecoder) (*Builder, error) {
	d, ok := base.(*diskDataset)
	if !ok || d == nil || revision != CompletedRevision {
		return nil, errors.New("offline completed revision requires a compact normalized base")
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || d.compact == nil || d.revision != BaseRevision || d.storage != s {
		return nil, errors.New("offline revision base is closed, incompatible or belongs to another storage owner")
	}
	b, err := s.newCompactBuilder(d.generation, d.compact.sources, d.compact.registry, decode, revision)
	if err != nil {
		return b, err
	}
	count := d.count
	b.expectedCount = &count
	return b, nil
}
