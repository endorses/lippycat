//go:build tui || all

package tui

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// Offline SIP framing is synchronous: media endpoints discovered in one packet
// are registered before the next ordered packet is analyzed. No worker may
// mutate a packet after its immutable detail has been written to storage.
type offlineSIPFactory struct {
	handler                            *TUISIPHandler
	streams                            int
	buffered                           int
	err                                error
	LastEvent                          *sharedsip.Event
	CurrentID                          offline.PacketID
	Flushing                           bool
	OnEvent                            func(offline.PacketID, sharedsip.Event) error
	maxMessage, maxStreams, maxContent int
}

const offlineSIPBufferLimit = 16 << 20
const offlineSIPStreamLimit = 4096

func newOfflineSIPFactory(h *TUISIPHandler, configs ...voip.Config) *offlineSIPFactory {
	f := &offlineSIPFactory{handler: h, maxMessage: sharedsip.MaxMessageSize, maxContent: sharedsip.MaxMessageSize, maxStreams: offlineSIPStreamLimit}
	if len(configs) > 0 {
		cfg := configs[0]
		if cfg.MaxStreams > 0 {
			f.maxStreams = min(f.maxStreams, cfg.MaxStreams)
		}
		if cfg.Security.MaxMessageSize > 0 {
			f.maxMessage = min(f.maxMessage, cfg.Security.MaxMessageSize)
		}
		if cfg.Security.MaxContentLength > 0 {
			f.maxContent = min(f.maxContent, cfg.Security.MaxContentLength)
		}
	}
	return f
}
func (f *offlineSIPFactory) Err() error      { return f.err }
func (f *offlineSIPFactory) Shutdown() error { return f.err }
func (f *offlineSIPFactory) New(n, t gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	f.streams++
	if f.streams > f.maxStreams && f.err == nil {
		f.err = fmt.Errorf("offline SIP reassembly exceeds %d streams", f.maxStreams)
	}
	return &offlineSIPStream{factory: f, network: n, transport: t}
}

type offlineSIPStream struct {
	factory            *offlineSIPFactory
	network, transport gopacket.Flow
	data               [2][]byte
	closed             bool
	packetID           [2]offline.PacketID
	timestamp          [2]time.Time
}

func (s *offlineSIPStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	i := 0
	if dir == reassembly.TCPDirServerToClient {
		i = 1
	}
	if len(tcp.Payload) > 0 {
		s.packetID[i] = s.factory.CurrentID
		s.timestamp[i] = ci.Timestamp
	}
	*start = true
	return s.factory.err == nil
}
func (s *offlineSIPStream) clear(i int) { s.factory.buffered -= len(s.data[i]); s.data[i] = nil }
func (s *offlineSIPStream) consume(i, n int) {
	s.factory.buffered -= n
	s.data[i] = bytes.Clone(s.data[i][n:])
	if len(s.data[i]) == 0 {
		s.data[i] = nil
	}
}
func (s *offlineSIPStream) ReassemblyComplete(_ reassembly.AssemblerContext) bool {
	if !s.closed {
		s.closed = true
		s.clear(0)
		s.clear(1)
		s.factory.streams--
	}
	return true
}
func (s *offlineSIPStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	if s.factory.err != nil {
		return
	}
	dir, _, _, skip := sg.Info()
	i := 0
	if dir == reassembly.TCPDirServerToClient {
		i = 1
	}
	if skip != 0 {
		s.clear(i)
	}
	n, _ := sg.Lengths()
	if n == 0 {
		return
	}
	data := sg.Fetch(n)
	consumedSG := 0
	// Feed bounded chunks so a large scatter/gather never becomes a large copy.
	for len(data) > 0 {
		room := s.factory.maxMessage - len(s.data[i])
		if room == 0 {
			s.factory.err = fmt.Errorf("offline SIP frame exceeds %d bytes", sharedsip.MaxMessageSize)
			return
		}
		take := min(room, len(data))
		if s.factory.buffered+take > offlineSIPBufferLimit {
			s.factory.err = fmt.Errorf("offline SIP framing exceeds %d buffered bytes", offlineSIPBufferLimit)
			return
		}
		previous := len(s.data[i])
		next := make([]byte, len(s.data[i])+take)
		copy(next, s.data[i])
		copy(next[len(s.data[i]):], data[:take])
		s.data[i] = next
		s.factory.buffered += take
		data = data[take:]
		origin := func(end int) (offline.PacketID, time.Time) {
			if ac != nil && !s.factory.Flushing {
				ci := ac.GetCaptureInfo()
				if id, ok := offlineSIPOrigin(ci); ok && id == s.factory.CurrentID {
					return id, ci.Timestamp
				}
			}
			ci := sg.CaptureInfo(consumedSG + end - previous - 1)
			if id, ok := offlineSIPOrigin(ci); ok {
				return id, ci.Timestamp
			}
			return s.packetID[i], s.timestamp[i]
		}
		s.parse(i, origin)
		consumedSG += take
		if s.factory.err != nil {
			return
		}
	}
}
func (s *offlineSIPStream) parse(i int, origin func(int) (offline.PacketID, time.Time)) {
	consumed := 0
	for len(s.data[i]) > 0 {
		b := s.data[i]
		lineEnd := bytes.IndexByte(b, '\n')
		if lineEnd < 0 {
			if len(b) == s.factory.maxMessage {
				s.clear(i)
			}
			return
		}
		if !sharedsip.IsStartLine(string(bytes.TrimSpace(b[:lineEnd]))) {
			s.consume(i, lineEnd+1)
			consumed += lineEnd + 1
			continue
		}
		end, sep := bytes.Index(b, []byte("\r\n\r\n")), 4
		if end < 0 {
			end, sep = bytes.Index(b, []byte("\n\n")), 2
		}
		if end < 0 {
			return
		}
		length := 0
		seen := false
		for _, line := range bytes.Split(b[:end], []byte("\n"))[1:] {
			key, val, ok := strings.Cut(string(line), ":")
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			if key != "content-length" && key != "l" {
				continue
			}
			value, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil || value < 0 || (seen && value != length) {
				s.factory.err = fmt.Errorf("offline SIP frame has invalid Content-Length")
				return
			}
			length = value
			seen = true
		}
		if length > s.factory.maxMessage-end-sep || length > s.factory.maxContent {
			s.factory.err = fmt.Errorf("offline SIP frame exceeds %d bytes", sharedsip.MaxMessageSize)
			return
		}
		total := end + sep + length
		if len(b) < total {
			return
		}
		nf, tf := s.network, s.transport
		if i == 1 {
			nf = nf.Reverse()
			tf = tf.Reverse()
		}
		src, dst := net.JoinHostPort(nf.Src().String(), tf.Src().String()), net.JoinHostPort(nf.Dst().String(), tf.Dst().String())
		packetID, ts := origin(consumed + total)
		event, err := sharedsip.Parse(b[:total], sharedsip.OptionsForEndpoints(ts, src, dst))
		if err == nil && s.factory.handler.HandleParsedSIPMessage(b[:total], event, src, dst, nf, tf) {
			s.factory.LastEvent = &event
			if s.factory.OnEvent != nil {
				s.factory.err = s.factory.OnEvent(packetID, event)
				if s.factory.err != nil {
					return
				}
			}
		}
		s.consume(i, total)
		consumed += total
	}
}

// Packet identity travels with reassembly pages, including repeated timestamps
// and delayed EOF delivery. It does not require a capture-sized lookup table.
type offlineSIPAssemblerContext struct{ info gopacket.CaptureInfo }

func (c offlineSIPAssemblerContext) GetCaptureInfo() gopacket.CaptureInfo { return c.info }
func offlineSIPContext(info gopacket.CaptureInfo, id offline.PacketID) offlineSIPAssemblerContext {
	info.AncillaryData = []any{id}
	return offlineSIPAssemblerContext{info}
}
func offlineSIPOrigin(info gopacket.CaptureInfo) (offline.PacketID, bool) {
	for _, v := range info.AncillaryData {
		if id, ok := v.(offline.PacketID); ok {
			return id, true
		}
	}
	return 0, false
}
