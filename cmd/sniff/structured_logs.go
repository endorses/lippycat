//go:build cli || all

package sniff

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/conntrack"
	dnsparser "github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/endorses/lippycat/internal/pkg/eventcoalesce"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/fileanalysis"
	"github.com/endorses/lippycat/internal/pkg/flowid"
	"github.com/endorses/lippycat/internal/pkg/logflags"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/logstream"
	logrecords "github.com/endorses/lippycat/internal/pkg/logstream/records"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var sniffLogFlags logflags.Values

func registerStructuredLogFlags(cmd *cobra.Command) {
	logflags.Register(cmd.PersistentFlags(), &sniffLogFlags, false)
}

type sniffLogSession struct {
	dispatcher     *events.Dispatcher
	identity       *flowid.Cache
	connections    *conntrack.Tracker
	dns            *dnsparser.Parser
	includeHeaders bool
	files          *fileanalysis.Analyzer
}

func withStructuredLogs(run func()) {
	dir := viper.GetString("logs.dir")
	if dir == "" {
		run()
		return
	}
	s, err := newSniffLogSession(dir)
	if err != nil {
		logger.Error("Failed to initialize structured protocol logs", "error", err)
		return
	}
	restore := capture.SetPacketObserver(s.observe)
	defer restore()
	defer func() {
		for _, ev := range s.connections.Close() {
			s.dispatcher.Enqueue(ev)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.dispatcher.Close(ctx); err != nil {
			logger.Error("Failed to close structured protocol logs", "error", err)
		}
	}()
	run()
}

func newSniffLogSession(dir string) (*sniffLogSession, error) {
	eventSize := viper.GetInt("events.queue_size")
	if eventSize <= 0 {
		eventSize = 20000
	}
	queueSize := viper.GetInt("logs.queue_size")
	if queueSize <= 0 {
		queueSize = 10000
	}
	d, err := events.NewDispatcher(events.Config{QueueSize: eventSize, SinkQueueSize: eventSize, DropPolicy: events.DropPolicy(viper.GetString("events.drop_policy"))})
	if err != nil {
		return nil, err
	}
	sink, err := logstream.New(logstream.Config{Directory: dir, Format: logstream.Format(viper.GetString("logs.format")), QueueSize: queueSize, RotateInterval: viper.GetDuration("logs.rotate_interval"), PostRotate: logstream.CommandHook(viper.GetString("logs.post_rotate_command"), 30*time.Second)})
	if err != nil {
		return nil, err
	}
	builders := map[string]struct {
		kind  events.Kind
		build logstream.Builder
	}{
		"dns": {events.KindDNS, logrecords.DNS}, "ssl": {events.KindTLS, logrecords.SSL},
		"http": {events.KindHTTP, logrecords.HTTP}, "smtp": {events.KindSMTP, logrecords.SMTP},
		"conn":  {events.KindConn, logrecords.Conn},
		"files": {events.KindFileMetadata, logrecords.Files},
	}
	for _, stream := range viper.GetStringSlice("logs.streams") {
		binding, ok := builders[strings.ToLower(stream)]
		if !ok {
			continue
		}
		if err := sink.Register(binding.kind, strings.ToLower(stream), binding.build); err != nil {
			return nil, err
		}
	}
	coalescedLogs, err := eventcoalesce.New(sink, eventcoalesce.Config{})
	if err != nil {
		return nil, err
	}
	if err := d.Register(coalescedLogs, events.KindDNS, events.KindTLS, events.KindHTTP, events.KindSMTP, events.KindConn, events.KindFileMetadata); err != nil {
		return nil, err
	}
	identity, err := flowid.NewCache(flowid.Config{MaxEntries: 100000, IdleTimeout: 5 * time.Minute})
	if err != nil {
		return nil, err
	}
	connections, err := conntrack.New(conntrack.Config{MaxFlows: 100000, IdleTimeout: 5 * time.Minute, HalfOpenTimeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	files, err := fileanalysis.New(fileanalysis.Config{MaxFileSize: viper.GetInt64("files.max_size"), MaxTotalSize: viper.GetInt64("files.total_size"), Extract: viper.GetBool("files.extract"), Directory: viper.GetString("files.extract_dir")})
	if err != nil {
		return nil, err
	}
	if err := sink.Start(context.Background()); err != nil {
		return nil, err
	}
	if err := d.Start(context.Background()); err != nil {
		_ = sink.Close(context.Background())
		return nil, err
	}
	return &sniffLogSession{dispatcher: d, identity: identity, connections: connections, dns: dnsparser.NewParser(), includeHeaders: viper.GetBool("logs.include_http_headers"), files: files}, nil
}

func (s *sniffLogSession) observe(info capture.PacketInfo) {
	pkt := info.Packet
	if pkt == nil {
		return
	}
	meta := protocolmeta.Enrich(pkt, nil, s.includeHeaders)
	flow, err := sniffFlow(meta)
	if err != nil {
		return
	}
	ts := time.Now()
	if pkt.Metadata() != nil && !pkt.Metadata().Timestamp.IsZero() {
		ts = pkt.Metadata().Timestamp
	}
	env, err := s.identity.Enrich(events.Envelope{Timestamp: ts, NodeID: "local", Flow: flow, CaptureScope: events.CaptureScopeFull})
	if err != nil {
		return
	}
	for _, ev := range observeConnection(s.connections, conntrack.FromPacket(pkt, env, meta.Protocol)) {
		s.dispatcher.Enqueue(ev)
	}
	if dm := s.dns.Parse(pkt); dm != nil {
		if dm.IsResponse {
			reverseEnvelope(&env)
		}
		e := events.NewDNSEvent(env)
		e.IsResponse = dm.IsResponse
		e.TransactionID, e.Query = dm.TransactionID, dm.QueryName
		e.QClass, e.QType, e.RCode = dnsCode(dm.QueryClass, map[string]uint16{"IN": 1}), dnsCode(dm.QueryType, map[string]uint16{"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "OPT": 41, "ANY": 255}), dnsCode(dm.ResponseCode, map[string]uint16{"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5})
		e.Authoritative, e.Truncated, e.RecursionDesired, e.RecursionAvailable = dm.Authoritative, dm.Truncated, dm.RecursionDesired, dm.RecursionAvailable
		for _, a := range dm.Answers {
			e.Answers = append(e.Answers, a.Data)
			e.TTLs = append(e.TTLs, time.Duration(a.TTL)*time.Second)
		}
		e.Rejected = strings.EqualFold(dm.ResponseCode, "REFUSED")
		s.dispatcher.Enqueue(e)
	}
	if meta.Tls != nil {
		s.dispatcher.Enqueue(sniffTLS(env, meta.Tls))
	}
	if meta.Http != nil {
		s.dispatcher.Enqueue(sniffHTTP(env, meta.Http, s.includeHeaders))
		if len(meta.Http.BodyPreview) > 0 && meta.Http.IsServer {
			fileEnv := env
			reverseEnvelope(&fileEnv)
			ev, content, analyzeErr := s.files.Analyze(fileanalysis.Observation{Envelope: fileEnv, Source: "HTTP", ContentType: meta.Http.ContentType, ContentEncoding: meta.Http.Headers["content-encoding"], Content: meta.Http.BodyPreview, TotalBytes: meta.Http.BodySize, Truncated: meta.Http.BodyTruncated})
			if analyzeErr == nil {
				s.dispatcher.Enqueue(ev)
				if content != nil {
					s.dispatcher.Enqueue(*content)
				}
			}
		}
	}
	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		s.emitSMTP(env, string(tcp.Payload))
	}
}

func observeConnection(t *conntrack.Tracker, observation conntrack.Observation) []events.ConnEvent {
	eventsOut, err := t.Observe(observation)
	if err != nil {
		logger.Debug("Skipping invalid connection observation", "error", err)
		return nil
	}
	return eventsOut
}

func dnsCode(v string, values map[string]uint16) uint16 { return values[strings.ToUpper(v)] }
func sniffFlow(m *data.PacketMetadata) (events.FlowTuple, error) {
	src, e := netip.ParseAddr(m.SrcIp)
	if e != nil {
		return events.FlowTuple{}, e
	}
	dst, e := netip.ParseAddr(m.DstIp)
	if e != nil {
		return events.FlowTuple{}, e
	}
	p := map[string]uint8{"tcp": 6, "udp": 17}[strings.ToLower(m.Transport)]
	if p == 0 {
		return events.FlowTuple{}, fmt.Errorf("unsupported transport")
	}
	return events.FlowTuple{Protocol: p, SourceAddress: src, DestinationAddress: dst, SourcePort: uint16(m.SrcPort), DestinationPort: uint16(m.DstPort)}, nil
}
func sniffTLS(env events.Envelope, m *data.TLSMetadata) events.TLSEvent {
	if m.IsServer {
		reverseEnvelope(&env)
	}
	e := events.NewTLSEvent(env)
	e.Version, e.ServerName, e.JA3, e.JA3S, e.JA4 = m.Version, m.Sni, m.Ja3, m.Ja3S, m.Ja4
	if m.SelectedCipher != 0 {
		e.Cipher = fmt.Sprintf("0x%04x", m.SelectedCipher)
	}
	if len(m.AlpnProtocols) > 0 {
		e.NextProtocol = m.AlpnProtocols[0]
	}
	e.Established = m.CorrelatedPeer || strings.EqualFold(m.HandshakeType, "ServerHello")
	return e
}
func sniffHTTP(env events.Envelope, m *data.HTTPMetadata, headers bool) events.HTTPEvent {
	if m.IsServer || strings.EqualFold(m.Type, "response") {
		reverseEnvelope(&env)
	}
	e := events.NewHTTPEvent(env)
	e.TransactionDepth = 1
	e.Method, e.Host, e.URI, e.Version, e.UserAgent = m.Method, m.Host, m.Path, m.Version, m.UserAgent
	if m.QueryString != "" {
		e.URI += "?" + m.QueryString
	}
	if m.ContentLength > 0 {
		if m.IsServer || strings.EqualFold(m.Type, "response") {
			e.ResponseBodyLength = uint64(m.ContentLength)
		} else {
			e.RequestBodyLength = uint64(m.ContentLength)
		}
	}
	e.StatusCode, e.StatusMessage = uint16(m.StatusCode), m.StatusReason
	if headers {
		e.Headers = map[string][]string{}
		for k, v := range m.Headers {
			e.Headers[k] = []string{v}
		}
		e.Referrer, e.Origin = m.Headers["referer"], m.Headers["origin"]
	}
	return e
}
func reverseEnvelope(e *events.Envelope) {
	e.Flow.SourceAddress, e.Flow.DestinationAddress = e.Flow.DestinationAddress, e.Flow.SourceAddress
	e.Flow.SourcePort, e.Flow.DestinationPort = e.Flow.DestinationPort, e.Flow.SourcePort
}
func (s *sniffLogSession) emitSMTP(env events.Envelope, payload string) {
	upper := strings.ToUpper(payload)
	if !strings.Contains(upper, "MAIL FROM:") && !strings.Contains(upper, "RCPT TO:") && !strings.Contains(upper, "SUBJECT:") && !strings.Contains(upper, "MESSAGE-ID:") {
		return
	}
	e := events.NewSMTPEvent(env)
	for _, line := range strings.Split(payload, "\n") {
		line = strings.TrimSpace(line)
		u := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(u, "MAIL FROM:"):
			e.MailFrom = strings.Trim(strings.TrimSpace(line[len("MAIL FROM:"):]), "<>")
		case strings.HasPrefix(u, "RCPT TO:"):
			e.Recipients = append(e.Recipients, strings.Trim(strings.TrimSpace(line[len("RCPT TO:"):]), "<>"))
		case strings.HasPrefix(u, "SUBJECT:"):
			e.Subject = strings.TrimSpace(line[len("SUBJECT:"):])
		case strings.HasPrefix(u, "MESSAGE-ID:"):
			e.MessageID = strings.TrimSpace(line[len("MESSAGE-ID:"):])
		}
	}
	s.dispatcher.Enqueue(e)
}
