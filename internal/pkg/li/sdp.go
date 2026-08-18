//go:build li

package li

import (
	"bytes"
	"net/netip"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// mediaEndpoint is an RTP endpoint advertised in SDP: the connection address
// (c= line) combined with a media port (m= line).
//
// Typed rather than string-keyed because LI runs on IPv6 networks, where
// "addr:port" concatenation is ambiguous.
type mediaEndpoint struct {
	addr netip.Addr
	port uint16
}

// String renders the endpoint in canonical host:port form (IPv6 bracketed).
func (e mediaEndpoint) String() string {
	return netip.AddrPortFrom(e.addr, e.port).String()
}

// sipMessageBody returns the message body of the SIP message carried by a
// packet, or "" when there is no SIP message or no body.
//
// VoIPMetadata.RawSIP is preferred but is not populated on the processor's
// packet pipeline, so this falls back to locating the SIP start line in the
// raw packet bytes — the same fallback the X2 encoder uses for its payload.
func sipMessageBody(pkt *types.PacketDisplay) string {
	if pkt == nil {
		return ""
	}

	var msg []byte
	if pkt.VoIPData != nil && len(pkt.VoIPData.RawSIP) > 0 {
		msg = pkt.VoIPData.RawSIP
	} else if len(pkt.RawData) > 0 {
		start := x2x3.FindSIPStart(pkt.RawData)
		if start < 0 {
			return ""
		}
		msg = pkt.RawData[start:]
	} else {
		return ""
	}

	// Headers and body are separated by an empty line. Accept LF-only line
	// endings as well; some stacks emit them despite RFC 3261 requiring CRLF.
	if i := bytes.Index(msg, []byte("\r\n\r\n")); i >= 0 {
		return string(msg[i+4:])
	}
	if i := bytes.Index(msg, []byte("\n\n")); i >= 0 {
		return string(msg[i+2:])
	}
	return ""
}

// parseSDPMediaEndpoints extracts the audio and video RTP endpoints from an SDP
// body, honouring both session-level and media-level connection addresses.
//
// A media section's own c= line follows its m= line, so each section's address
// is resolved when the section ends (at the next m= line, or at the end of the
// body) rather than when its port is read.
//
// Streams with port 0 (declined or removed) and unspecified connection
// addresses (0.0.0.0 / :: on-hold form) are skipped: no media flows there, so
// matching against them could only mislabel. Bodies that are not SDP (or
// multipart bodies wrapping SDP) parse harmlessly — only c=/m= lines matter.
func parseSDPMediaEndpoints(body string) []mediaEndpoint {
	if body == "" {
		return nil
	}

	var (
		endpoints   []mediaEndpoint
		sessionAddr netip.Addr // session-level c=
		mediaAddr   netip.Addr // c= within the section currently being read
		mediaPort   uint16     // port of that section (0: none, or not audio/video)
		inMedia     bool
	)

	// flush records the media section that has just ended.
	flush := func() {
		if mediaPort == 0 {
			return
		}
		addr := mediaAddr
		if !addr.IsValid() {
			addr = sessionAddr
		}
		if !addr.IsValid() || addr.IsUnspecified() {
			return
		}
		e := mediaEndpoint{addr: addr, port: mediaPort}
		for _, existing := range endpoints {
			if existing == e {
				return
			}
		}
		endpoints = append(endpoints, e)
	}

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "c=IN IP4 "), strings.HasPrefix(line, "c=IN IP6 "):
			addr, ok := parseSDPConnectionAddr(line)
			if !ok {
				continue
			}
			if inMedia {
				mediaAddr = addr
			} else if !sessionAddr.IsValid() {
				sessionAddr = addr
			}

		case strings.HasPrefix(line, "m="):
			flush()
			inMedia = true
			mediaAddr = netip.Addr{}
			mediaPort = 0
			if !strings.HasPrefix(line, "m=audio ") && !strings.HasPrefix(line, "m=video ") {
				continue
			}
			if port, ok := parseSDPMediaPort(line); ok {
				mediaPort = port
			}
		}
	}
	flush()

	return endpoints
}

// parseSDPConnectionAddr parses the address of an SDP c= line, stripping any
// multicast TTL / address-count suffix ("c=IN IP4 224.2.1.1/127/3").
func parseSDPConnectionAddr(line string) (netip.Addr, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return netip.Addr{}, false
	}
	value := fields[2]
	if i := strings.Index(value, "/"); i >= 0 {
		value = value[:i]
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// parseSDPMediaPort parses the port of an SDP m= line, stripping the optional
// port-count suffix ("m=audio 49170/2 RTP/AVP 0"). Port 0 means the stream is
// declined, which is reported as absent.
func parseSDPMediaPort(line string) (uint16, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, false
	}
	value := fields[1]
	if i := strings.Index(value, "/"); i >= 0 {
		value = value[:i]
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		return 0, false
	}
	return uint16(port), true
}

// packetEndpoints returns the source and destination endpoints of a captured
// packet. Either may be invalid when the address or port is missing/unparsable.
func packetEndpoints(pkt *types.PacketDisplay) (src, dst mediaEndpoint, ok bool) {
	src, srcOK := parseEndpoint(pkt.SrcIP, pkt.SrcPort)
	dst, dstOK := parseEndpoint(pkt.DstIP, pkt.DstPort)
	return src, dst, srcOK && dstOK
}

// parseEndpoint builds a mediaEndpoint from the string address/port pair
// carried on PacketDisplay.
func parseEndpoint(ipStr, portStr string) (mediaEndpoint, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return mediaEndpoint{}, false
	}
	port, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
	if err != nil || port == 0 {
		return mediaEndpoint{}, false
	}
	return mediaEndpoint{addr: addr.Unmap(), port: uint16(port)}, true
}
