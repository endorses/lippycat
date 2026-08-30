package eventanalysis

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	emailparser "github.com/endorses/lippycat/internal/pkg/email"
	"github.com/endorses/lippycat/internal/pkg/events"
	httpparser "github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	tlsparser "github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

const maxReassembledApplicationBytes = 1 << 20

type reassemblyContext struct {
	source       Source
	scope        events.CaptureScope
	partial      bool
	protocolHint string
}

type applicationFactory struct{ runtime *Runtime }

func (f *applicationFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	return &applicationStream{runtime: f.runtime, netFlow: netFlow, tcpFlow: tcpFlow, email: emailparser.NewParser(), partial: tcp == nil || !tcp.SYN}
}

type applicationStream struct {
	runtime           *Runtime
	netFlow, tcpFlow  gopacket.Flow
	buffer            []byte
	email             *emailparser.Parser
	emailMetadata     types.EmailMetadata
	smtpInData        bool
	smtpInBody        bool
	smtpBody          strings.Builder
	smtpBodySize      int
	smtpBodyTruncated bool
	partial           bool
	protocolHint      string
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
	var ctx reassemblyContext
	ok := len(ci.AncillaryData) != 0
	if ok {
		ctx, ok = ci.AncillaryData[0].(reassemblyContext)
	}
	if !ok {
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
	s.buffer = append(s.buffer, chunk...)
	s.parse(ctx, ci)
}

func (s *applicationStream) ReassemblyComplete(reassembly.AssemblerContext) bool {
	if len(s.buffer) != 0 {
		s.runtime.stats.Invalid++
	}
	return true
}

func (s *applicationStream) parse(ctx reassemblyContext, ci gopacket.CaptureInfo) {
	if ctx.protocolHint != "" {
		s.protocolHint = ctx.protocolHint
	}
	srcPort, dstPort := flowPort(s.tcpFlow.Src()), flowPort(s.tcpFlow.Dst())
	switch {
	case s.protocolHint == "tls" || isTLSPort(srcPort) || isTLSPort(dstPort):
		s.parseTLS(ctx, ci)
	case s.protocolHint == "http" || isHTTPPort(srcPort) || isHTTPPort(dstPort):
		s.parseHTTP(ctx, ci)
	case s.protocolHint == "smtp" || isSMTPPort(srcPort) || isSMTPPort(dstPort):
		s.parseSMTP(ctx, ci, isSMTPPort(srcPort))
	}
}

func (s *applicationStream) parseHTTP(ctx reassemblyContext, ci gopacket.CaptureInfo) {
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
			s.buffer = s.buffer[frameEnd:]
			s.partial = true
			continue
		}
		bodyLength := metadata.ContentLength
		if bodyLength < 0 || bodyLength > maxReassembledApplicationBytes {
			s.buffer = s.buffer[frameEnd:]
			s.partial = true
			s.runtime.stats.Invalid++
			continue
		}
		if strings.Contains(strings.ToLower(metadata.Headers["transfer-encoding"]), "chunked") {
			messageEnd, body, complete, valid := chunkedMessage(s.buffer, frameEnd)
			if !valid {
				s.buffer = s.buffer[frameEnd:]
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
			s.buffer = s.buffer[messageEnd:]
			s.emit(ctx, ci, nil, protocolmeta.HTTPToProto(metadata, s.runtime.cfg.IncludeHTTPHeaders), nil)
			continue
		}
		messageEnd := frameEnd + int(bodyLength)
		if len(s.buffer) < messageEnd {
			return
		}
		if bodyLength != 0 {
			metadata.BodyPreview = string(s.buffer[frameEnd:messageEnd])
			metadata.BodySize = int(bodyLength)
		}
		s.buffer = s.buffer[messageEnd:]
		s.emit(ctx, ci, nil, protocolmeta.HTTPToProto(metadata, s.runtime.cfg.IncludeHTTPHeaders), nil)
	}
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

func (s *applicationStream) parseTLS(ctx reassemblyContext, ci gopacket.CaptureInfo) {
	for len(s.buffer) >= 5 {
		length := int(binary.BigEndian.Uint16(s.buffer[3:5])) + 5
		if length > maxReassembledApplicationBytes || s.buffer[0] < 20 || s.buffer[0] > 24 || s.buffer[1] != 3 {
			s.buffer = s.buffer[1:]
			s.partial = true
			continue
		}
		if len(s.buffer) < length {
			return
		}
		frame := s.buffer[:length]
		s.buffer = s.buffer[length:]
		metadata := tlsparser.NewParser().ParsePayload(frame)
		if metadata != nil {
			s.emit(ctx, ci, protocolmeta.TLSToProto(metadata), nil, nil)
		}
	}
}

func (s *applicationStream) parseSMTP(ctx reassemblyContext, ci gopacket.CaptureInfo, fromServer bool) {
	for {
		end := bytes.IndexByte(s.buffer, '\n')
		if end < 0 {
			return
		}
		line := strings.TrimRight(string(s.buffer[:end+1]), "\r\n")
		s.buffer = s.buffer[end+1:]
		if !fromServer && s.smtpInData {
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
				s.emit(ctx, ci, nil, nil, metadata)
				s.smtpInData, s.smtpInBody = false, false
				s.smtpBody.Reset()
				s.smtpBodySize, s.smtpBodyTruncated = 0, false
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
		}
		if !recognized && s.emailMetadata.Subject == "" && s.emailMetadata.MessageID == "" {
			continue
		}
		metadata := &data.EmailMetadata{MailFrom: s.emailMetadata.MailFrom, RcptTo: append([]string(nil), s.emailMetadata.RcptTo...), Subject: s.emailMetadata.Subject, MessageId: s.emailMetadata.MessageID}
		s.emit(ctx, ci, nil, nil, metadata)
	}
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
	r.tcpAssembler.AssembleCaptureInfo(packet.NetworkLayer().NetworkFlow(), tcp, gopacket.CaptureInfo{
		Timestamp:     timestamp,
		AncillaryData: []interface{}{reassemblyContext{source: source, scope: scope, partial: partial, protocolHint: protocolHint}},
	})
}
