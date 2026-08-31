// Package eventanalysis provides the shared, stateful normalized-event analysis
// runtime used by processor, tap, sniff, and local capture frontends.
package eventanalysis

import (
	"context"
	"fmt"
	"mime"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/conntrack"
	dnsparser "github.com/endorses/lippycat/internal/pkg/dns"
	emailparser "github.com/endorses/lippycat/internal/pkg/email"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/fileanalysis"
	"github.com/endorses/lippycat/internal/pkg/flowid"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Source identifies the analysis authority and capture provenance for an input.
type Source struct {
	NodeID, CaptureSource, InterfaceName, InputFile string
	InterfaceIndex                                  uint32
	ProcessorNodeIDs                                []string
	CaptureScope                                    events.CaptureScope
	Partial                                         bool
}

// Config controls bounded analysis state. Dispatcher lifecycle remains owned by
// the caller so sinks can be registered before it is started.
type Config struct {
	Dispatcher              *events.Dispatcher
	Flow                    flowid.Config
	Connections             conntrack.Config
	Files                   fileanalysis.Config
	IncludeHTTPHeaders      bool
	IncludeEmailBodyPreview bool
	Now                     func() time.Time
	ExpiryInterval          time.Duration
	// LiveExpiry advances connection expiry from the wall clock when capture is
	// idle. Leave it disabled for deterministic offline replay, where packet
	// timestamps and EOF exclusively drive the capture clock.
	LiveExpiry bool
	// LosslessDelivery drains the dispatcher before every admission. It is
	// intended for deterministic offline analysis only; live callers should
	// retain the default non-blocking, drop-on-pressure behavior.
	LosslessDelivery bool
}

type Stats struct{ Observed, Emitted, Invalid, Dropped uint64 }

type Runtime struct {
	mu            sync.Mutex
	cfg           Config
	identity      *flowid.Cache
	connections   *conntrack.Tracker
	tcpAssembler  *capture.TCPAssembler
	tcpNamespaces map[reassemblySourceKey]uint64
	nextNamespace uint64
	files         *fileanalysis.Analyzer
	dns           *dnsparser.Parser
	nextExpiry    time.Time
	closed        bool
	stats         Stats
	expiryStop    chan struct{}
	expiryDone    chan struct{}
	stopExpiry    sync.Once
}

func New(cfg Config) (*Runtime, error) {
	if cfg.Dispatcher == nil {
		return nil, fmt.Errorf("event analysis dispatcher is required")
	}
	if cfg.Flow.MaxEntries <= 0 {
		cfg.Flow.MaxEntries = 100000
	}
	if cfg.Flow.IdleTimeout <= 0 {
		cfg.Flow.IdleTimeout = 5 * time.Minute
	}
	if cfg.Connections.MaxFlows <= 0 {
		cfg.Connections.MaxFlows = 100000
	}
	if cfg.Connections.IdleTimeout <= 0 {
		cfg.Connections.IdleTimeout = 5 * time.Minute
	}
	if cfg.Connections.HalfOpenTimeout <= 0 {
		cfg.Connections.HalfOpenTimeout = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ExpiryInterval <= 0 {
		cfg.ExpiryInterval = time.Second
	}
	r := &Runtime{cfg: cfg}
	if err := r.resetState(); err != nil {
		return nil, err
	}
	if cfg.LiveExpiry {
		r.expiryStop = make(chan struct{})
		r.expiryDone = make(chan struct{})
		go r.runLiveExpiry()
	}
	return r, nil
}

func (r *Runtime) runLiveExpiry() {
	defer close(r.expiryDone)
	ticker := time.NewTicker(r.cfg.ExpiryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.Expire(r.cfg.Now())
		case <-r.expiryStop:
			return
		}
	}
}

func (r *Runtime) stopLiveExpiry() {
	if r.expiryStop == nil {
		return
	}
	r.stopExpiry.Do(func() { close(r.expiryStop) })
	<-r.expiryDone
}

func (r *Runtime) resetState() error {
	var err error
	r.identity, err = flowid.NewCache(r.cfg.Flow)
	if err != nil {
		return fmt.Errorf("initialize flow identity: %w", err)
	}
	r.connections, err = conntrack.New(r.cfg.Connections)
	if err != nil {
		return fmt.Errorf("initialize connection tracking: %w", err)
	}
	r.files, err = fileanalysis.New(r.cfg.Files)
	if err != nil {
		return fmt.Errorf("initialize file analysis: %w", err)
	}
	r.dns = dnsparser.NewParser()
	r.resetReassembly()
	r.nextExpiry = time.Time{}
	return nil
}

// ObserveCaptured analyzes protobuf-backed analyzer output and the original
// packet bytes. Live/default delivery never blocks on dispatcher capacity;
// lossless offline delivery may wait for sinks to drain.
func (r *Runtime) ObserveCaptured(source Source, packets []*data.CapturedPacket) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("event analysis runtime is closed")
	}
	var firstErr error
	invalid := 0
	var newest time.Time
	for _, raw := range packets {
		ts, err := r.observeCaptured(source, raw)
		if err != nil {
			r.stats.Invalid++
			invalid++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if ts.After(newest) {
			newest = ts
		}
	}
	r.expireAfterBatch(newest)
	if invalid > 0 {
		return fmt.Errorf("analyze captured packets: %d of %d invalid: %w", invalid, len(packets), firstErr)
	}
	return nil
}

// ObservePacket adapts local capture through the existing protocol analyzers
// before entering the canonical stateful path.
func (r *Runtime) ObservePacket(source Source, info capture.PacketInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("event analysis runtime is closed")
	}
	if info.Packet == nil {
		r.stats.Invalid++
		return fmt.Errorf("capture packet is required")
	}
	if source.InterfaceName == "" {
		source.InterfaceName = info.Interface
	}
	meta := protocolmeta.Enrich(info.Packet, nil, r.cfg.IncludeHTTPHeaders)
	if meta == nil {
		r.stats.Invalid++
		return fmt.Errorf("capture packet metadata enrichment failed")
	}
	if parsed := r.dns.Parse(info.Packet); parsed != nil {
		meta.Dns = dnsToProto(parsed)
	}
	protocolHint := applicationProtocolHint(meta)
	// Stateful application protocols are emitted from the bounded TCP
	// reassembly path below. Clear packet-local guesses to avoid premature or
	// duplicate events when a message spans segments.
	if _, ok := info.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		meta.Tls, meta.Http, meta.Email = nil, nil, nil
	}
	timestamp := time.Time{}
	if packetMetadata := info.Packet.Metadata(); packetMetadata != nil {
		timestamp = packetMetadata.Timestamp
	}
	timestampNS := int64(0)
	if !timestamp.IsZero() {
		timestampNS = timestamp.UnixNano()
	}
	observedAt, err := r.observeCapturedWithHint(source, &data.CapturedPacket{
		Data:        info.Packet.Data(),
		TimestampNs: timestampNS,
		LinkType:    uint32(info.LinkType),
		Metadata:    meta,
	}, protocolHint)
	if err != nil {
		r.stats.Invalid++
		return err
	}
	r.expireAfterBatch(observedAt)
	return nil
}

func dnsToProto(m *types.DNSMetadata) *data.DNSMetadata {
	if m == nil {
		return nil
	}
	out := &data.DNSMetadata{TransactionId: uint32(m.TransactionID), IsResponse: m.IsResponse, Opcode: m.Opcode, ResponseCode: m.ResponseCode, Authoritative: m.Authoritative, Truncated: m.Truncated, RecursionDesired: m.RecursionDesired, RecursionAvailable: m.RecursionAvailable, AuthenticatedData: m.AuthenticatedData, CheckingDisabled: m.CheckingDisabled, QuestionCount: uint32(m.QuestionCount), AnswerCount: uint32(m.AnswerCount), AuthorityCount: uint32(m.AuthorityCount), AdditionalCount: uint32(m.AdditionalCount), QueryName: m.QueryName, QueryType: m.QueryType, QueryClass: m.QueryClass, QueryResponseTimeMs: m.QueryResponseTimeMs, CorrelatedQuery: m.CorrelatedQuery, TunnelingScore: m.TunnelingScore, EntropyScore: m.EntropyScore}
	for _, a := range m.Answers {
		out.Answers = append(out.Answers, &data.DNSAnswer{Name: a.Name, Type: a.Type, Class: a.Class, Ttl: a.TTL, Data: a.Data})
	}
	return out
}

func (r *Runtime) smtpToProto(payload []byte) *data.EmailMetadata {
	parser := emailparser.NewParser()
	metadata := &types.EmailMetadata{}
	recognized := false
	for _, line := range strings.Split(string(payload), "\n") {
		if parser.ParseLine(line, metadata, false) {
			recognized = true
		}
		parser.ParseDataHeader(line, metadata)
	}
	if !recognized && metadata.Subject == "" && metadata.MessageID == "" {
		return nil
	}
	return &data.EmailMetadata{MailFrom: metadata.MailFrom, RcptTo: append([]string(nil), metadata.RcptTo...), Subject: metadata.Subject, MessageId: metadata.MessageID}
}

func (r *Runtime) observeCaptured(source Source, raw *data.CapturedPacket) (time.Time, error) {
	return r.observeCapturedWithHint(source, raw, "")
}

func (r *Runtime) observeCapturedWithHint(source Source, raw *data.CapturedPacket, protocolHint string) (time.Time, error) {
	if raw == nil || raw.Metadata == nil {
		return time.Time{}, fmt.Errorf("captured packet metadata is required")
	}
	ts := time.Unix(0, raw.TimestampNs)
	if raw.TimestampNs == 0 {
		ts = r.cfg.Now()
	}
	// Transported captures carry interface provenance per packet. Preserve an
	// explicitly supplied source value, but fill it from the packet when the
	// batch-level source cannot describe packets from multiple interfaces.
	if source.InterfaceName == "" {
		source.InterfaceName = raw.InterfaceName
	}
	if source.InterfaceIndex == 0 {
		source.InterfaceIndex = raw.InterfaceIndex
	}
	scope := source.CaptureScope
	if scope == "" {
		scope = events.CaptureScopeFull
	}
	if len(raw.MatchedFilterIds) > 0 {
		scope = events.CaptureScopeFiltered
	}
	env, err := r.envelope(source, raw.Metadata, ts, scope, source.Partial || scope == events.CaptureScopeFiltered)
	if err != nil {
		return time.Time{}, err
	}
	r.stats.Observed++
	packet := gopacket.NewPacket(raw.Data, layers.LinkType(raw.LinkType), gopacket.NoCopy)
	connEvents, err := r.connections.Observe(conntrack.FromPacket(packet, env, raw.Metadata.Protocol))
	if err != nil {
		return time.Time{}, fmt.Errorf("observe connection: %w", err)
	}
	for _, ev := range connEvents {
		r.emit(ev)
	}
	if _, tcp := packet.TransportLayer().(*layers.TCP); tcp {
		// Packet-local analyzers may recognize an incomplete TCP segment. Wait
		// for bounded reassembly so all paths emit the same canonical event at
		// the final-byte timestamp. The result remains useful as a parser hint
		// for protocols detected on non-standard ports.
		metadata := *raw.Metadata
		if protocolHint == "" {
			protocolHint = applicationProtocolHint(raw.Metadata)
		}
		metadata.Tls, metadata.Http, metadata.Email = nil, nil, nil
		r.emitMetadata(env, &metadata)
		r.observeTCP(source, packet, ts, scope, source.Partial || scope == events.CaptureScopeFiltered, protocolHint)
	} else {
		// Keep compatibility with metadata-only captured packets.
		r.emitMetadata(env, raw.Metadata)
	}
	return ts, nil
}

func applicationProtocolHint(meta *data.PacketMetadata) string {
	if meta == nil {
		return ""
	}
	switch {
	case meta.Http != nil:
		return "http"
	case meta.Tls != nil:
		return "tls"
	case meta.Email != nil:
		return "smtp"
	}
	switch strings.ToLower(meta.Protocol) {
	case "http", "tls", "smtp":
		return strings.ToLower(meta.Protocol)
	default:
		return ""
	}
}

func (r *Runtime) expireAfterBatch(newest time.Time) {
	if !newest.IsZero() && (r.nextExpiry.IsZero() || !newest.Before(r.nextExpiry)) {
		r.expire(newest)
		r.nextExpiry = newest.Add(r.cfg.ExpiryInterval)
	}
}

func (r *Runtime) envelope(source Source, meta *data.PacketMetadata, ts time.Time, scope events.CaptureScope, partial bool) (events.Envelope, error) {
	flow, err := FlowTuple(meta)
	if err != nil {
		return events.Envelope{}, err
	}
	nodeID := source.NodeID
	if nodeID == "" {
		nodeID = source.CaptureSource
	}
	env := events.Envelope{Timestamp: ts, NodeID: nodeID, Flow: flow, CaptureScope: scope, Partial: partial, Provenance: events.SourceProvenance{CaptureSource: source.CaptureSource, InterfaceName: source.InterfaceName, InterfaceIndex: source.InterfaceIndex, InputFile: source.InputFile, ProcessorNodeIDs: append([]string(nil), source.ProcessorNodeIDs...)}}
	return r.identity.Enrich(env)
}

func (r *Runtime) emit(ev events.Event) {
	r.stats.Emitted++
	if r.cfg.LosslessDelivery {
		if err := r.cfg.Dispatcher.Flush(context.Background()); err != nil {
			r.stats.Dropped++
			return
		}
	}
	if !r.cfg.Dispatcher.Enqueue(ev) {
		r.stats.Dropped++
	}
}

func (r *Runtime) emitMetadata(env events.Envelope, meta *data.PacketMetadata) {
	if meta.Dns != nil {
		r.emit(MapDNS(env, meta.Dns))
	}
	if meta.Email != nil {
		e := events.NewSMTPEvent(env)
		e.MailFrom = meta.Email.MailFrom
		e.Recipients = append([]string(nil), meta.Email.RcptTo...)
		e.Subject = meta.Email.Subject
		e.MessageID = meta.Email.MessageId
		r.emit(e)
		r.emitSMTPFiles(env, meta.Email)
	}
	if meta.Tls != nil {
		r.emit(MapTLS(env, meta.Tls))
	}
	if meta.Http != nil {
		r.emit(MapHTTP(env, meta.Http, r.cfg.IncludeHTTPHeaders))
		r.emitHTTPFile(env, meta.Http)
	}
}

func (r *Runtime) emitSMTPFiles(env events.Envelope, meta *data.EmailMetadata) {
	if !r.cfg.IncludeEmailBodyPreview || len(meta.BodyPreview) == 0 || !strings.HasPrefix(strings.ToLower(meta.ContentType), "multipart/") {
		return
	}
	items, err := fileanalysis.SMTPAttachments([]byte(meta.BodyPreview), meta.ContentType, r.cfg.Files.MaxFileSize)
	if err != nil {
		r.stats.Invalid++
		return
	}
	for _, item := range items {
		item.Envelope, item.TotalBytes, item.Truncated = env, uint64(len(item.Content)), item.Truncated || meta.BodyTruncated
		ev, content, e := r.files.Analyze(item)
		if e != nil {
			r.stats.Invalid++
			continue
		}
		r.emit(ev)
		if content != nil {
			r.emit(*content)
		}
	}
}

func (r *Runtime) emitHTTPFile(env events.Envelope, meta *data.HTTPMetadata) {
	if len(meta.BodyPreview) == 0 || !(meta.IsServer || strings.EqualFold(meta.Type, "response")) {
		return
	}
	ReverseFlow(&env.Flow)
	filename := ""
	if d := meta.Headers["content-disposition"]; d != "" {
		if _, p, e := mime.ParseMediaType(d); e == nil {
			filename = p["filename"]
		}
	}
	ev, content, err := r.files.Analyze(fileanalysis.Observation{Envelope: env, Source: "HTTP", Filename: filename, ContentType: meta.ContentType, ContentEncoding: meta.Headers["content-encoding"], Content: meta.BodyPreview, TotalBytes: meta.BodySize, Truncated: meta.BodyTruncated})
	if err != nil {
		r.stats.Invalid++
		return
	}
	r.emit(ev)
	if content != nil {
		r.emit(*content)
	}
}

func (r *Runtime) expire(now time.Time) {
	if r.tcpAssembler != nil {
		r.tcpAssembler.FlushCloseOlderThan(now.Add(-r.cfg.Connections.IdleTimeout))
	}
	for _, ev := range r.connections.Expire(now) {
		r.emit(ev)
	}
}
func (r *Runtime) Expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.expire(now)
	}
}
func (r *Runtime) EOF() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if r.tcpAssembler != nil {
		r.tcpAssembler.FlushAll()
	}
	for _, ev := range r.connections.Close() {
		r.emit(ev)
	}
}
func (r *Runtime) Reset() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("event analysis runtime is closed")
	}
	if r.tcpAssembler != nil {
		r.tcpAssembler.FlushAll()
	}
	for _, ev := range r.connections.Close() {
		r.emit(ev)
	}
	return r.resetState()
}
func (r *Runtime) Close() {
	r.stopLiveExpiry()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if r.tcpAssembler != nil {
		r.tcpAssembler.FlushAll()
	}
	for _, ev := range r.connections.Close() {
		r.emit(ev)
	}
	r.closed = true
}
func (r *Runtime) Stats() Stats { r.mu.Lock(); defer r.mu.Unlock(); return r.stats }

func FlowTuple(meta *data.PacketMetadata) (events.FlowTuple, error) {
	src, e := netip.ParseAddr(meta.SrcIp)
	if e != nil {
		return events.FlowTuple{}, fmt.Errorf("source IP %q: %w", meta.SrcIp, e)
	}
	dst, e := netip.ParseAddr(meta.DstIp)
	if e != nil {
		return events.FlowTuple{}, fmt.Errorf("destination IP %q: %w", meta.DstIp, e)
	}
	var p uint8
	switch strings.ToLower(meta.Transport) {
	case "tcp":
		p = 6
	case "udp":
		p = 17
	case "icmp":
		p = 1
	case "icmpv6", "icmp6":
		p = 58
	default:
		return events.FlowTuple{}, fmt.Errorf("unsupported transport %q", meta.Transport)
	}
	return events.FlowTuple{Protocol: p, SourceAddress: src, DestinationAddress: dst, SourcePort: uint16(meta.SrcPort), DestinationPort: uint16(meta.DstPort)}, nil
}
