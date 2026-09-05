package offline

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

type PacketID uint64
type DatasetGeneration uint64
type QueryGeneration uint64
type RequestID uint64

// Token accompanies every asynchronous request/result, including errors. The
// model rejects obsolete tokens and closes any resources they transfer.
type Token struct {
	Dataset DatasetGeneration
	Query   QueryGeneration
	Request RequestID
}

// PageRequest bounds both row count and decoded bytes. Row is a logical query
// position, never an index into an in-memory dataset-sized slice.
type PageRequest struct {
	Token    Token
	Row      uint64
	Limit    uint32
	MaxBytes uint64
}

type Page struct {
	Token Token
	Row   uint64
	Rows  []Summary
	lease *pageLease
}

// Close releases the shared byte budget for this page. Rows and any copies of
// the page must no longer be used afterward. Page value copies share one lease;
// closing more than once is safe. Empty and zero-value pages need no cleanup.
func (p Page) Close() error {
	if p.lease != nil {
		p.lease.close()
	}
	return nil
}

// Statistics counts each logical packet once. Cardinality counters remain
// independently bounded; TruncatedCardinality names counters that reached caps.
type Statistics struct {
	Packets, Bytes               uint64
	First, Last                  time.Time
	Protocols                    map[string]uint64
	SourceCounts                 map[string]uint64
	DestinationCounts            map[string]uint64
	MinPacketSize, MaxPacketSize uint64
	Sources, Destinations        uint64
	TruncatedCardinality         []string
}

// Predicate is an immutable, concurrency-safe filter snapshot supplied by the
// caller. The offline package never imports the build-tagged TUI filter package.
type Predicate func(Summary) bool

// QueryProgress reports cumulative scan and match counts. A final scan count
// equal to Total does not publish a query: manifest completion can still fail.
type QueryProgress struct {
	Token                   Token
	Scanned, Matched, Total uint64
}

type QuerySpec struct {
	Token       Token
	Description []string
	Match       Predicate // nil matches all packets
	// Progress runs synchronously at scan start, periodically, and at scan end.
	// It must return promptly and must not call dataset or query methods.
	Progress func(QueryProgress)
}

// Flow identifies a bidirectional TCP/UDP relationship. Empty node and transport
// zero are wildcards; invalid endpoints/zero ports never match. Translate the
// local event node to "Local" in the session adapter before querying.
type Flow struct {
	Source, Destination netip.AddrPort
	Transport           uint8
	Node                string
}

// Query is an immutable completed ordered match set. All IDs/offsets remain on
// disk. Iterate pins the snapshot until return, visits one detail at a time,
// and stops on context cancellation or callback error. Close releases the query
// only after active readers finish; it must run outside the UI update loop.
type Query interface {
	Token() Token
	Count() uint64
	Statistics() Statistics
	Page(context.Context, PageRequest) (Page, error)
	Iterate(context.Context, func(Detail) error) error
	Close() error
}

// Dataset is published only after analyzer EOF drain and all streams flush.
// Query/Related return completed snapshots or errors, never partial matches.
// Dataset Close joins readers, removes owned storage, and surfaces cleanup errors.
type Dataset interface {
	Generation() DatasetGeneration
	Count() uint64
	Statistics() Statistics
	Query(context.Context, QuerySpec) (Query, error)
	Related(context.Context, Token, Flow) (Query, error)
	Detail(context.Context, Token, PacketID) (Detail, error)
	PinDetail(context.Context, Token, PacketID) (*DetailPin, error)
	Resources() ResourceUsage
	Close() error
}

// Detail contains an owned finalized PacketDisplay, including all protocol
// metadata and effective raw bytes. It must not alias analyzer scratch storage.
type Detail struct {
	Token                          Token
	ID                             PacketID
	Source                         SourcePosition
	CapturedLength, OriginalLength uint32
	Packet                         types.PacketDisplay
}

type SourcePosition struct {
	ArgumentIndex uint32
	Path          string // exact input identity, never a basename
	InterfaceID   uint32 // PCAPNG interface / reassembly domain
	Sequence      uint64 // logical source sequence, zero-based
}

// RecordHeader describes logical frame identity, not a Go memory layout to
// write with unsafe. The codec adds magic, checksum and reserved fields and validates
// PayloadBytes against the record/allocation budgets before allocating.
type RecordHeader struct {
	Version      uint16
	Kind         uint16
	PayloadBytes uint64
	ID           PacketID
}

const RecordSchemaVersion uint16 = 1

// ResourceLimits are explicit validated budgets, shared across the current and
// replacement session. Zero is invalid; defaults are selected after baselines.
// CacheBytes includes decoded rows/details, pins, prefetch and in-flight reads.
type ResourceLimits struct {
	Directory                             string
	DiskBytes, CacheBytes, MaxRecordBytes uint64
	MaxSources                            uint32
}

func (r ResourceLimits) Validate() error {
	if r.Directory == "" || r.DiskBytes == 0 || r.CacheBytes == 0 || r.MaxRecordBytes == 0 || r.MaxSources == 0 {
		return fmt.Errorf("offline resource limits require a directory and positive disk, cache, record and source limits")
	}
	if r.MaxRecordBytes > r.CacheBytes || r.MaxRecordBytes > r.DiskBytes {
		return fmt.Errorf("offline maximum record bytes must fit both cache and disk budgets")
	}
	return nil
}

// ResourceUsage categories are disjoint. DiskBytes includes manifests, summaries,
// details, offsets, matches and unfinished files from both retained sessions.
// Memory categories sum against CacheBytes; runtime/analyzer/reassembly overhead
// is measured separately and is not a promise of a hard process RSS ceiling.
type ResourceUsage struct {
	DiskBytes                                              uint64
	CachedBytes, PinnedBytes, PrefetchBytes, InFlightBytes uint64
}

type State string

const (
	Opening    State = "opening"
	Indexing   State = "indexing"
	Ready      State = "ready"
	Cancelling State = "cancelling"
	Cancelled  State = "cancelled"
	Failed     State = "failed"
)

type Progress struct {
	Token                                   Token
	State                                   State
	Sources                                 uint32
	LogicalPackets, ScannedBytes, DiskBytes uint64
	ByteProgressKnown                       bool
	Elapsed                                 time.Duration
}

// Session owns one isolated indexing operation. Cancel is nonblocking. Wait and
// Close run in workers, not Update. Wait transfers a completed Dataset exactly
// once on success; failure/cancellation cleans up all unpublished resources.
// The TUI adapter additionally owns bounded event/call histories and frozen
// analysis settings, publishing them atomically with this dataset.
type Session interface {
	Generation() DatasetGeneration
	Progress() Progress
	Cancel()
	Wait(context.Context) (Dataset, error)
	Close() error
}

// TimestampRegressionError rejects an entire build; already-analyzed records
// cannot be repaired by warning or local sorting. Equal timestamps are allowed.
type TimestampRegressionError struct {
	Source            SourcePosition
	Previous, Current time.Time
}

func (e *TimestampRegressionError) Error() string {
	return fmt.Sprintf("offline source %q (argument %d, interface %d) timestamp regressed at logical sequence %d: %s before %s; use chronologically ordered inputs", e.Source.Path, e.Source.ArgumentIndex, e.Source.InterfaceID, e.Source.Sequence, e.Current.Format(time.RFC3339Nano), e.Previous.Format(time.RFC3339Nano))
}
