// Package sip provides output-neutral, stateless SIP message parsing.
package sip

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

const MaxMessageSize = 64 * 1024

var (
	ErrNotSIP                 = errors.New("not a SIP message")
	ErrMalformedContentLength = errors.New("malformed SIP Content-Length")
)

// RequestMethods is the single method set used for SIP detection and framing.
var RequestMethods = [...]string{
	"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK",
	"SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE",
}

// CompactHeaders contains the RFC 3261 compact forms plus compact forms defined
// by the SIP extension RFCs used by lippycat.
var CompactHeaders = map[string]string{
	"a": "accept-contact", "b": "referred-by", "c": "content-type",
	"d": "request-disposition", "e": "content-encoding", "f": "from",
	"i": "call-id", "j": "reject-contact", "k": "supported",
	"l": "content-length", "m": "contact", "n": "identity-info",
	"o": "event", "r": "refer-to", "s": "subject", "t": "to",
	"u": "allow-events", "v": "via", "x": "session-expires", "y": "identity",
}

type ParseOptions struct {
	Timestamp                   time.Time
	SourceIP, DestinationIP     string
	SourcePort, DestinationPort uint16
}

func OptionsForEndpoints(timestamp time.Time, source, destination string) ParseOptions {
	opts := ParseOptions{Timestamp: timestamp}
	if host, port, err := net.SplitHostPort(source); err == nil {
		opts.SourceIP = host
		if value, parseErr := strconv.ParseUint(port, 10, 16); parseErr == nil {
			opts.SourcePort = uint16(value)
		}
	}
	if host, port, err := net.SplitHostPort(destination); err == nil {
		opts.DestinationIP = host
		if value, parseErr := strconv.ParseUint(port, 10, 16); parseErr == nil {
			opts.DestinationPort = uint16(value)
		}
	}
	return opts
}

// SIPEvent is the normalized interpretation of exactly one SIP message.
type SIPEvent struct {
	Timestamp                                          time.Time
	StartLine, Method, RequestURI, CSeqMethod          string
	ResponseCode                                       int
	CallID, From, To, FromUser, ToUser, FromURI, ToURI string
	FromTag, ToTag, PAssertedIdentity, ContentType     string
	Headers                                            map[string]string
	Body                                               []byte
	SDP                                                []byte
	SourceIP, DestinationIP                            string
	SourcePort, DestinationPort                        uint16
}

// Event is retained as the short spelling for consumers.
type Event = SIPEvent

func IsRequestMethod(method string) bool {
	for _, candidate := range RequestMethods {
		if method == candidate {
			return true
		}
	}
	return false
}

func IsStartLine(line string) bool {
	line = strings.TrimRight(line, "\x00\r\n")
	if strings.HasPrefix(line, "SIP/2.0 ") {
		return true
	}
	fields := strings.Fields(line)
	return len(fields) == 3 && IsRequestMethod(fields[0]) && fields[2] == "SIP/2.0"
}

func Parse(data []byte, opts ParseOptions) (SIPEvent, error) {
	var ev SIPEvent
	if len(data) > MaxMessageSize {
		data = data[:MaxMessageSize]
	}
	headerEnd, sepLen := bytes.Index(data, []byte("\r\n\r\n")), 4
	if headerEnd < 0 {
		headerEnd, sepLen = bytes.Index(data, []byte("\n\n")), 2
	}
	if headerEnd < 0 {
		headerEnd, sepLen = len(data), 0
	}
	lines := bytes.Split(data[:headerEnd], []byte("\n"))
	if len(lines) == 0 {
		return ev, ErrNotSIP
	}
	ev.StartLine = strings.TrimSpace(string(lines[0]))
	if !IsStartLine(ev.StartLine) {
		return ev, ErrNotSIP
	}
	fields := strings.Fields(ev.StartLine)
	if fields[0] == "SIP/2.0" {
		if len(fields) < 2 || len(fields[1]) != 3 {
			return ev, ErrNotSIP
		}
		code, err := strconv.Atoi(fields[1])
		if err != nil || code < 100 || code > 699 {
			return ev, ErrNotSIP
		}
		ev.Method, ev.ResponseCode = "RESPONSE", code
	} else {
		ev.Method, ev.RequestURI = fields[0], fields[1]
	}
	ev.Headers = make(map[string]string)
	var contentLengths []string
	var previousHeader string
	for _, raw := range lines[1:] {
		raw = bytes.TrimSuffix(raw, []byte("\r"))
		if len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t') {
			if previousHeader != "" {
				continuation := strings.TrimSpace(string(raw))
				if continuation != "" {
					ev.Headers[previousHeader] += " " + continuation
					if previousHeader == "content-length" {
						contentLengths[len(contentLengths)-1] = ev.Headers[previousHeader]
					}
				}
			}
			continue
		}
		line := bytes.TrimSpace(raw)
		if len(line) == 0 {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			previousHeader = ""
			continue
		}
		name := strings.ToLower(strings.TrimSpace(string(line[:colon])))
		if full, ok := CompactHeaders[name]; ok {
			name = full
		}
		value := strings.TrimSpace(string(line[colon+1:]))
		previousHeader = name
		if name == "content-length" {
			contentLengths = append(contentLengths, value)
		}
		ev.Headers[name] = value
	}
	bodyStart := headerEnd + sepLen
	if bodyStart < len(data) {
		ev.Body = append([]byte(nil), data[bodyStart:]...)
	}
	if len(contentLengths) > 0 {
		value := strings.TrimSpace(contentLengths[0])
		for _, duplicate := range contentLengths[1:] {
			if strings.TrimSpace(duplicate) != value {
				return SIPEvent{}, ErrMalformedContentLength
			}
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > MaxMessageSize {
			return SIPEvent{}, ErrMalformedContentLength
		}
		if len(ev.Body) < n {
			return SIPEvent{}, ErrMalformedContentLength
		}
		ev.Body = ev.Body[:n]
	}
	ev.Timestamp, ev.SourceIP, ev.DestinationIP = opts.Timestamp, opts.SourceIP, opts.DestinationIP
	ev.SourcePort, ev.DestinationPort = opts.SourcePort, opts.DestinationPort
	ev.CallID, ev.From, ev.To = ev.Headers["call-id"], ev.Headers["from"], ev.Headers["to"]
	ev.FromURI, ev.ToURI = URI(ev.From), URI(ev.To)
	ev.FromUser, ev.ToUser = User(ev.FromURI), User(ev.ToURI)
	ev.FromTag, ev.ToTag = Tag(ev.From), Tag(ev.To)
	ev.PAssertedIdentity, ev.ContentType = ev.Headers["p-asserted-identity"], ev.Headers["content-type"]
	mediaType := ev.ContentType
	if semicolon := strings.IndexByte(mediaType, ';'); semicolon >= 0 {
		mediaType = mediaType[:semicolon]
	}
	if strings.EqualFold(strings.TrimSpace(mediaType), "application/sdp") {
		ev.SDP = append([]byte(nil), ev.Body...)
	}
	cseq := strings.Fields(ev.Headers["cseq"])
	if len(cseq) >= 2 {
		ev.CSeqMethod = strings.ToUpper(cseq[1])
	}
	return ev, nil
}

func URI(header string) string {
	if left := strings.IndexByte(header, '<'); left >= 0 {
		if right := strings.IndexByte(header[left+1:], '>'); right >= 0 {
			return header[left+1 : left+1+right]
		}
	}
	lower := strings.ToLower(header)
	start := strings.Index(lower, "sip:")
	if start < 0 {
		start = strings.Index(lower, "sips:")
	}
	if start < 0 {
		return ""
	}
	end := len(header)
	for i, r := range header[start:] {
		if r == ';' || r == ' ' || r == '\r' || r == '\n' || r == '>' {
			end = start + i
			break
		}
	}
	return header[start:end]
}

func User(uri string) string {
	lower := strings.ToLower(uri)
	start := 0
	if strings.HasPrefix(lower, "sips:") {
		start = 5
	} else if strings.HasPrefix(lower, "sip:") {
		start = 4
	} else {
		return ""
	}
	if at := strings.IndexByte(uri[start:], '@'); at >= 0 {
		return uri[start : start+at]
	}
	return ""
}

func Tag(header string) string {
	for _, parameter := range strings.Split(header, ";")[1:] {
		name, value, found := strings.Cut(strings.TrimSpace(parameter), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "tag") {
			continue
		}
		value = strings.TrimSpace(value)
		if end := strings.IndexAny(value, " >\r\n"); end >= 0 {
			value = value[:end]
		}
		return value
	}
	return ""
}

func CSeqMethod(value string) string {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return ""
	}
	return strings.ToUpper(fields[1])
}
