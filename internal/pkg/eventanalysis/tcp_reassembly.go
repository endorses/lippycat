package eventanalysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	emailparser "github.com/endorses/lippycat/internal/pkg/email"
	"github.com/endorses/lippycat/internal/pkg/events"
	httpparser "github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/pkg/reassembly"
	tlsparser "github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const maxReassembledApplicationBytes = 1 << 20

var endpointNamespacedNetwork = gopacket.RegisterEndpointType(1000, gopacket.EndpointTypeMetadata{
	Name: "namespaced-network",
	Formatter: func(raw []byte) string {
		return fmt.Sprintf("%x", raw)
	},
})

type reassemblyContext struct {
	source       Source
	scope        events.CaptureScope
	partial      bool
	protocolHint string
	netFlow      gopacket.Flow
	tcpFlow      gopacket.Flow
	flowKey      reassemblyFlowKey
}

// reassemblySourceKey prevents packets captured by independent producers or
// inputs from being combined merely because they share a network 5-tuple.
type reassemblySourceKey struct {
	nodeID         string
	captureSource  string
	interfaceName  string
	interfaceIndex uint32
	inputFile      string
}

type reassemblyFlowKey struct {
	namespace uint64
	endpointA string
	endpointB string
}

func sourceReassemblyKey(source Source) reassemblySourceKey {
	return reassemblySourceKey{
		nodeID: source.NodeID, captureSource: source.CaptureSource,
		interfaceName: source.InterfaceName, interfaceIndex: source.InterfaceIndex,
		inputFile: source.InputFile,
	}
}

type applicationFactory struct{ runtime *Runtime }

func (f *applicationFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	ci := ac.GetCaptureInfo()
	var flowKey reassemblyFlowKey
	if len(ci.AncillaryData) != 0 {
		if ctx, ok := ci.AncillaryData[0].(reassemblyContext); ok {
			netFlow, tcpFlow = ctx.netFlow, ctx.tcpFlow
			flowKey = ctx.flowKey
		}
	}
	return &applicationStream{runtime: f.runtime, netFlow: netFlow, tcpFlow: tcpFlow, flowKey: flowKey, email: emailparser.NewParser(), partial: tcp == nil || !tcp.SYN}
}

type applicationStream struct {
	runtime           *Runtime
	netFlow, tcpFlow  gopacket.Flow
	flowKey           reassemblyFlowKey
	buffer            []byte
	marks             []reassemblyMark
	email             *emailparser.Parser
	emailMetadata     types.EmailMetadata
	smtpInData        bool
	smtpInBody        bool
	smtpBody          strings.Builder
	smtpBodySize      int
	smtpBodyTruncated bool
	smtpContext       reassemblyMark
	smtpContextSet    bool
	partial           bool
	protocolHint      string
	tlsHandshake      []byte
	tlsRecordVersion  uint16
	tlsContext        reassemblyMark
	tlsContextSet     bool
	httpCloseBody     *types.HTTPMetadata
	httpCloseContext  reassemblyMark
}

type reassemblyMark struct {
	end int
	ctx reassemblyContext
	ci  gopacket.CaptureInfo
}

func (*applicationStream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = true
	return true
}

func (s *applicationStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	available, _ := sg.Lengths()
	if available == 0 {
		return
	}
	ci := sg.CaptureInfo(available - 1)
	if _, ok := captureContext(ci); !ok {
		s.partial = true
		return
	}
	_, _, _, skip := sg.Info()
	if skip != 0 {
		s.partial = true
	}
	chunk := sg.Fetch(available)
	if len(s.buffer)+len(chunk) > maxReassembledApplicationBytes {
		s.buffer = s.buffer[:0]
		s.partial = true
		s.runtime.stats.Invalid++
		return
	}
	s.appendMarks(sg, available)
	s.buffer = append(s.buffer, chunk...)
	s.parse()
}

func (s *applicationStream) ReassemblyComplete(reassembly.AssemblerContext) bool {
	delete(s.runtime.activeTCPFlows, s.flowKey)
	if s.httpCloseBody != nil {
		metadata := s.httpCloseBody
		metadata.BodyPreview = string(s.buffer)
		metadata.BodySize = len(s.buffer)
		metadata.ContentLength = int64(len(s.buffer))
		mark := s.contextThrough(len(s.buffer))
		mark = mergeCaptureMarks(s.httpCloseContext, mark)
		s.consume(len(s.buffer))
		s.emit(mark.ctx, mark.ci, nil, protocolmeta.HTTPToProto(metadata, s.runtime.cfg.IncludeHTTPHeaders), nil)
		s.httpCloseBody = nil
	}
	if len(s.buffer) != 0 {
		s.runtime.stats.Invalid++
	}
	return true
}

func (s *applicationStream) parse() {
	if len(s.marks) != 0 && s.marks[len(s.marks)-1].ctx.protocolHint != "" {
		s.protocolHint = s.marks[len(s.marks)-1].ctx.protocolHint
	}
	srcPort, dstPort := flowPort(s.tcpFlow.Src()), flowPort(s.tcpFlow.Dst())
	switch {
	case s.protocolHint == "tls" || isTLSPort(srcPort) || isTLSPort(dstPort):
		s.parseTLS()
	case s.protocolHint == "http" || isHTTPPort(srcPort) || isHTTPPort(dstPort):
		s.parseHTTP()
	case s.protocolHint == "smtp" || isSMTPPort(srcPort) || isSMTPPort(dstPort):
		s.parseSMTP(isSMTPPort(srcPort))
	}
}

func (s *applicationStream) parseHTTP() {
	if s.httpCloseBody != nil {
		return
	}
	for {
		end := bytes.Index(s.buffer, []byte("\r\n\r\n"))
		separator := 4
		if end < 0 {
			end, separator = bytes.Index(s.buffer, []byte("\n\n")), 2
		}
		if end < 0 {
			return
		}
		frameEnd := end + separator
		metadata := httpparser.NewParser().ParsePayload(s.buffer[:frameEnd])
		if metadata == nil {
			s.consume(frameEnd)
			s.partial = true
			continue
		}
		bodyLength := metadata.ContentLength
		if bodyLength < 0 || bodyLength > maxReassembledApplicationBytes {
			s.consume(frameEnd)
			s.partial = true
			s.runtime.stats.Invalid++
			continue
		}
		if strings.Contains(strings.ToLower(metadata.Headers["transfer-encoding"]), "chunked") {
			messageEnd, body, complete, valid := chunkedMessage(s.buffer, frameEnd)
			if !valid {
				s.consume(frameEnd)
				s.partial = true
				s.runtime.stats.Invalid++
				continue
			}
			if !complete {
				return
			}
			metadata.BodyPreview = string(body)
			metadata.BodySize = len(body)
			metadata.ContentLength = int64(len(body))
			mark := s.contextThrough(messageEnd)
			s.consume(messageEnd)
			s.emit(mark.ctx, mark.ci, nil, protocolmeta.HTTPToProto(metadata, s.runtime.cfg.IncludeHTTPHeaders), nil)
			continue
		}
		_, hasContentLength := metadata.Headers["content-length"]
		if metadata.StatusCode != 0 && !hasContentLength && responseMayHaveCloseDelimitedBody(metadata.StatusCode) {
			s.httpCloseBody = metadata
			s.httpCloseContext = s.contextThrough(frameEnd)
			s.consume(frameEnd)
			return
		}
		messageEnd := frameEnd + int(bodyLength)
		if len(s.buffer) < messageEnd {
			return
		}
		if bodyLength != 0 {
			metadata.BodyPreview = string(s.buffer[frameEnd:messageEnd])
			metadata.BodySize = int(bodyLength)
		}
		mark := s.contextThrough(messageEnd)
		s.consume(messageEnd)
		s.emit(mark.ctx, mark.ci, nil, protocolmeta.HTTPToProto(metadata, s.runtime.cfg.IncludeHTTPHeaders), nil)
	}
}

func responseMayHaveCloseDelimitedBody(status int) bool {
	return status >= 200 && status != 204 && status != 304
}

func chunkedMessage(payload []byte, bodyStart int) (int, []byte, bool, bool) {
	position := bodyStart
	body := make([]byte, 0)
	for {
		lineEnd := bytes.IndexByte(payload[position:], '\n')
		if lineEnd < 0 {
			return 0, nil, false, true
		}
		lineEnd += position
		sizeText, _, _ := strings.Cut(strings.TrimSpace(string(payload[position:lineEnd])), ";")
		size, err := strconv.ParseUint(strings.TrimSpace(sizeText), 16, 64)
		if err != nil || size > maxReassembledApplicationBytes || uint64(len(body))+size > maxReassembledApplicationBytes {
			return 0, nil, false, false
		}
		position = lineEnd + 1
		if size == 0 {
			for {
				trailerEnd := bytes.IndexByte(payload[position:], '\n')
				if trailerEnd < 0 {
					return 0, nil, false, true
				}
				trailerEnd += position
				if len(bytes.TrimSpace(payload[position:trailerEnd])) == 0 {
					return trailerEnd + 1, body, true, true
				}
				position = trailerEnd + 1
			}
		}
		chunkEnd := position + int(size)
		if chunkEnd < position || chunkEnd >= len(payload) {
			return 0, nil, false, true
		}
		body = append(body, payload[position:chunkEnd]...)
		position = chunkEnd
		switch {
		case len(payload[position:]) >= 2 && payload[position] == '\r' && payload[position+1] == '\n':
			position += 2
		case payload[position] == '\n':
			position++
		default:
			return 0, nil, false, false
		}
	}
}

func (s *applicationStream) parseTLS() {
	for len(s.buffer) >= 5 {
		length := int(binary.BigEndian.Uint16(s.buffer[3:5])) + 5
		if length > maxReassembledApplicationBytes || s.buffer[0] < 20 || s.buffer[0] > 24 || s.buffer[1] != 3 {
			s.consume(1)
			s.partial = true
			continue
		}
		if len(s.buffer) < length {
			return
		}
		frame := s.buffer[:length]
		mark := s.contextThrough(length)
		s.consume(length)
		if frame[0] != tlsparser.RecordTypeHandshake {
			continue
		}
		if len(s.tlsHandshake)+len(frame)-5 > maxReassembledApplicationBytes {
			s.tlsHandshake = s.tlsHandshake[:0]
			s.partial = true
			s.runtime.stats.Invalid++
			continue
		}
		if len(s.tlsHandshake) == 0 {
			s.tlsRecordVersion = binary.BigEndian.Uint16(frame[1:3])
		}
		s.tlsHandshake = append(s.tlsHandshake, frame[5:]...)
		s.mergeTLSContext(mark)
		for len(s.tlsHandshake) >= 4 {
			handshakeLength := int(s.tlsHandshake[1])<<16 | int(s.tlsHandshake[2])<<8 | int(s.tlsHandshake[3])
			messageEnd := handshakeLength + 4
			if messageEnd > maxReassembledApplicationBytes {
				s.tlsHandshake = s.tlsHandshake[:0]
				s.partial = true
				s.runtime.stats.Invalid++
				break
			}
			if len(s.tlsHandshake) < messageEnd {
				break
			}
			metadata := tlsparser.NewParser().ParseHandshake(s.tlsRecordVersion, s.tlsHandshake[:messageEnd])
			s.tlsHandshake = s.tlsHandshake[messageEnd:]
			if metadata != nil {
				s.emit(s.tlsContext.ctx, s.tlsContext.ci, protocolmeta.TLSToProto(metadata), nil, nil)
			}
		}
		if len(s.tlsHandshake) == 0 {
			s.tlsContextSet = false
		}
	}
}

func (s *applicationStream) parseSMTP(fromServer bool) {
	for {
		end := bytes.IndexByte(s.buffer, '\n')
		if end < 0 {
			return
		}
		line := strings.TrimRight(string(s.buffer[:end+1]), "\r\n")
		mark := s.contextThrough(end + 1)
		s.consume(end + 1)
		if !fromServer && s.smtpInData {
			s.mergeSMTPContext(mark)
			if line == "." {
				metadata := &data.EmailMetadata{
					MailFrom: s.emailMetadata.MailFrom, RcptTo: append([]string(nil), s.emailMetadata.RcptTo...),
					Subject: s.emailMetadata.Subject, MessageId: s.emailMetadata.MessageID,
					ContentType: s.emailMetadata.ContentType, BodySize: int32(s.smtpBodySize), // #nosec G115 -- bounded by the reassembly limit
					BodyTruncated: s.smtpBodyTruncated,
				}
				if s.runtime.cfg.IncludeEmailBodyPreview {
					metadata.BodyPreview = s.smtpBody.String()
				}
				s.emit(s.smtpContext.ctx, s.smtpContext.ci, nil, nil, metadata)
				s.smtpInData, s.smtpInBody = false, false
				s.smtpBody.Reset()
				s.smtpBodySize, s.smtpBodyTruncated = 0, false
				s.smtpContextSet = false
				continue
			}
			if !s.smtpInBody {
				s.email.ParseDataHeader(line, &s.emailMetadata)
				s.smtpInBody = line == ""
				continue
			}
			s.captureSMTPBody(line)
			continue
		}
		recognized := s.email.ParseLine(line, &s.emailMetadata, fromServer)
		if recognized && !fromServer && s.emailMetadata.Command == "DATA" {
			s.smtpInData = true
			s.smtpInBody = false
			s.smtpContext, s.smtpContextSet = mark, true
		}
		if !recognized && s.emailMetadata.Subject == "" && s.emailMetadata.MessageID == "" {
			continue
		}
		metadata := &data.EmailMetadata{MailFrom: s.emailMetadata.MailFrom, RcptTo: append([]string(nil), s.emailMetadata.RcptTo...), Subject: s.emailMetadata.Subject, MessageId: s.emailMetadata.MessageID}
		s.emit(mark.ctx, mark.ci, nil, nil, metadata)
	}
}

func (s *applicationStream) appendMarks(sg reassembly.ScatterGather, available int) {
	base := len(s.buffer)
	for offset := 0; offset < available; offset++ {
		ci := sg.CaptureInfo(offset)
		ctx, ok := captureContext(ci)
		if !ok {
			s.partial = true
			continue
		}
		if len(s.marks) == 0 || !sameCaptureMark(s.marks[len(s.marks)-1], ctx, ci) {
			s.marks = append(s.marks, reassemblyMark{end: base + offset + 1, ctx: ctx, ci: ci})
		} else {
			s.marks[len(s.marks)-1].end = base + offset + 1
		}
	}
}

func captureContext(ci gopacket.CaptureInfo) (reassemblyContext, bool) {
	if len(ci.AncillaryData) == 0 {
		return reassemblyContext{}, false
	}
	ctx, ok := ci.AncillaryData[0].(reassemblyContext)
	return ctx, ok
}

func sameCaptureMark(mark reassemblyMark, ctx reassemblyContext, ci gopacket.CaptureInfo) bool {
	return mark.ci.Timestamp.Equal(ci.Timestamp) && mark.ctx.scope == ctx.scope && mark.ctx.partial == ctx.partial && sameSource(mark.ctx.source, ctx.source) && mark.ctx.protocolHint == ctx.protocolHint
}

func sameSource(a, b Source) bool {
	if a.NodeID != b.NodeID || a.CaptureSource != b.CaptureSource || a.InterfaceName != b.InterfaceName || a.InterfaceIndex != b.InterfaceIndex || a.InputFile != b.InputFile || a.CaptureScope != b.CaptureScope || a.Partial != b.Partial || len(a.ProcessorNodeIDs) != len(b.ProcessorNodeIDs) {
		return false
	}
	for i := range a.ProcessorNodeIDs {
		if a.ProcessorNodeIDs[i] != b.ProcessorNodeIDs[i] {
			return false
		}
	}
	return true
}

func (s *applicationStream) contextThrough(end int) reassemblyMark {
	var result reassemblyMark
	for _, mark := range s.marks {
		result = mark
		if mark.end >= end {
			break
		}
	}
	// Re-scan provenance flags because result is replaced as capture runs are
	// traversed and the conservative flags must survive until frame completion.
	for _, mark := range s.marks {
		if mark.ctx.scope == events.CaptureScopeFiltered {
			result.ctx.scope = events.CaptureScopeFiltered
		}
		result.ctx.partial = result.ctx.partial || mark.ctx.partial
		if mark.end >= end {
			break
		}
	}
	return result
}

func (s *applicationStream) consume(count int) {
	s.buffer = s.buffer[count:]
	kept := s.marks[:0]
	for _, mark := range s.marks {
		if mark.end <= count {
			continue
		}
		mark.end -= count
		kept = append(kept, mark)
	}
	s.marks = kept
}

func (s *applicationStream) mergeTLSContext(mark reassemblyMark) {
	if !s.tlsContextSet {
		s.tlsContext, s.tlsContextSet = mark, true
		return
	}
	s.tlsContext.ci = mark.ci
	if mark.ctx.scope == events.CaptureScopeFiltered {
		s.tlsContext.ctx.scope = events.CaptureScopeFiltered
	}
	s.tlsContext.ctx.partial = s.tlsContext.ctx.partial || mark.ctx.partial
}

func (s *applicationStream) mergeSMTPContext(mark reassemblyMark) {
	if !s.smtpContextSet {
		s.smtpContext, s.smtpContextSet = mark, true
		return
	}
	s.smtpContext = mergeCaptureMarks(s.smtpContext, mark)
}

func mergeCaptureMarks(first, last reassemblyMark) reassemblyMark {
	if first.ctx.scope == events.CaptureScopeFiltered {
		last.ctx.scope = events.CaptureScopeFiltered
	}
	last.ctx.partial = last.ctx.partial || first.ctx.partial
	if last.ci.Timestamp.IsZero() {
		last.ci = first.ci
	}
	if last.ctx.source.NodeID == "" {
		last.ctx.source = first.ctx.source
	}
	return last
}

func (s *applicationStream) captureSMTPBody(line string) {
	lineBytes := len(line) + 1
	s.smtpBodySize += lineBytes
	if !s.runtime.cfg.IncludeEmailBodyPreview || s.smtpBodyTruncated {
		return
	}
	limit := s.runtime.cfg.Files.MaxFileSize
	if limit <= 0 || limit > maxReassembledApplicationBytes {
		limit = maxReassembledApplicationBytes
	}
	remaining := int(limit) - s.smtpBody.Len()
	if remaining <= 0 {
		s.smtpBodyTruncated = true
		return
	}
	text := line
	if s.smtpBody.Len() != 0 {
		text = "\n" + text
	}
	if len(text) > remaining {
		text = text[:remaining]
		s.smtpBodyTruncated = true
	}
	s.smtpBody.WriteString(text)
}

func (s *applicationStream) emit(ctx reassemblyContext, ci gopacket.CaptureInfo, tls *data.TLSMetadata, http *data.HTTPMetadata, email *data.EmailMetadata) {
	metadata := &data.PacketMetadata{
		SrcIp: s.netFlow.Src().String(), DstIp: s.netFlow.Dst().String(),
		SrcPort: uint32(flowPort(s.tcpFlow.Src())), DstPort: uint32(flowPort(s.tcpFlow.Dst())),
		Transport: "tcp", Tls: tls, Http: http, Email: email,
	}
	scope := ctx.scope
	if scope == "" {
		scope = events.CaptureScopeFull
	}
	env, err := s.runtime.envelope(ctx.source, metadata, ci.Timestamp, scope, ctx.partial || s.partial)
	if err != nil {
		s.runtime.stats.Invalid++
		return
	}
	service := ""
	switch {
	case http != nil:
		service = "HTTP"
	case tls != nil:
		service = "TLS"
	case email != nil:
		service = "SMTP"
	}
	if err := s.runtime.connections.SetService(env, service); err != nil {
		s.runtime.stats.Invalid++
	}
	s.runtime.emitMetadata(env, metadata)
	s.partial = false
}

func flowPort(endpoint gopacket.Endpoint) uint16 {
	raw := endpoint.Raw()
	if len(raw) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(raw)
}

func isHTTPPort(port uint16) bool {
	switch port {
	case 80, 3000, 8000, 8080, 8888:
		return true
	default:
		return false
	}
}

func isTLSPort(port uint16) bool { return port == 443 || port == 8443 }

func isSMTPPort(port uint16) bool {
	switch port {
	case 25, 465, 587, 2525:
		return true
	default:
		return false
	}
}

func (r *Runtime) resetReassembly() {
	r.tcpAssembler = capture.NewTCPAssembler(&applicationFactory{runtime: r})
	r.activeTCPFlows = make(map[reassemblyFlowKey]struct{})
}

func (r *Runtime) observeTCP(source Source, packet gopacket.Packet, timestamp time.Time, scope events.CaptureScope, partial bool, protocolHint string) {
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok || packet.NetworkLayer() == nil {
		return
	}
	if len(tcp.Payload) == 0 && !tcp.SYN && !tcp.FIN && !tcp.RST {
		return
	}
	if scope == "" {
		scope = events.CaptureScopeFull
	}
	namespace := sourceNamespace(source)
	netFlow := packet.NetworkLayer().NetworkFlow()
	portFlow := tcp.TransportFlow()
	flowKey := canonicalReassemblyFlowKey(namespace, netFlow, portFlow)
	if _, exists := r.activeTCPFlows[flowKey]; !exists {
		if len(r.activeTCPFlows) >= r.cfg.MaxReassemblyStreams {
			closed := r.tcpAssembler.FlushAll()
			r.stats.ReassemblyEvicted += uint64(closed)
		}
		r.activeTCPFlows[flowKey] = struct{}{}
	}
	namespacedFlow := gopacket.NewFlow(endpointNamespacedNetwork,
		namespacedEndpoint(namespace, netFlow.Src()),
		namespacedEndpoint(namespace, netFlow.Dst()),
	)
	r.tcpAssembler.AssembleCaptureInfo(namespacedFlow, tcp, gopacket.CaptureInfo{
		Timestamp:     timestamp,
		AncillaryData: []interface{}{reassemblyContext{source: source, scope: scope, partial: partial, protocolHint: protocolHint, netFlow: netFlow, tcpFlow: portFlow, flowKey: flowKey}},
	})
}

func sourceNamespace(source Source) uint64 {
	key := sourceReassemblyKey(source)
	h := sha256.New()
	for _, value := range []string{key.nodeID, key.captureSource, key.interfaceName, strconv.FormatUint(uint64(key.interfaceIndex), 10), key.inputFile} {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return binary.BigEndian.Uint64(h.Sum(nil))
}

func canonicalReassemblyFlowKey(namespace uint64, netFlow, tcpFlow gopacket.Flow) reassemblyFlowKey {
	a := fmt.Sprintf("%d:%x:%d:%x", netFlow.Src().EndpointType(), netFlow.Src().Raw(), tcpFlow.Src().EndpointType(), tcpFlow.Src().Raw())
	b := fmt.Sprintf("%d:%x:%d:%x", netFlow.Dst().EndpointType(), netFlow.Dst().Raw(), tcpFlow.Dst().EndpointType(), tcpFlow.Dst().Raw())
	if b < a {
		a, b = b, a
	}
	return reassemblyFlowKey{namespace: namespace, endpointA: a, endpointB: b}
}

func namespacedEndpoint(namespace uint64, endpoint gopacket.Endpoint) []byte {
	identity := make([]byte, 16, 16+len(endpoint.Raw()))
	binary.BigEndian.PutUint64(identity, namespace)
	binary.BigEndian.PutUint64(identity[8:], uint64(endpoint.EndpointType()))
	identity = append(identity, endpoint.Raw()...)
	sum := sha256.Sum256(identity)
	return sum[:16]
}
