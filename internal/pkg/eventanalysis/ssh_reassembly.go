package eventanalysis

import (
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	httpparser "github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/reassembly"
	sshparser "github.com/endorses/lippycat/internal/pkg/ssh"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Reserve the worst-case parser packet and owned ordered-list strings for both
// halves before admitting a recognized flow. Reassembly pages and dispatcher
// snapshots have their own existing bounded owners. The reservation remains
// until connection completion/expiry, including terminal parser tombstones.
const sshFlowReservationBytes int64 = 4*sshparser.MaxPacketBytes + 2*sshparser.MaxIdentificationBytes + 4096

type SSHStats struct {
	ActiveFlows                                    int
	ReservedBytes                                  int64
	Admitted, Rejected, Banners, Complete, Partial uint64
}

type sshConnection struct {
	halves [2]sshHalf
}

type sshHalf struct {
	parser         sshparser.Stream
	identification *sshparser.Identification
	last           reassemblyMark
	observed       bool
	partial        bool
	filtered       bool
	terminal       bool
}

// An embedded, allocation-free prefix probe recognizes a split SSH signature
// without allocating a parser for unrelated payload. Only the four signature
// bytes are retained; bounded prelude text is skipped at line boundaries.
type sshIdentificationProbe struct {
	matched, lineBytes, scanned, lines int
	partial, filtered, disabled, gap   bool
	last                               reassemblyMark
}

func sshHalfIndex(direction reassembly.TCPFlowDirection) int {
	if direction == reassembly.TCPDirServerToClient {
		return 1
	}
	return 0
}

func (s *applicationStream) observeSSHRole(tcp *layers.TCP, direction reassembly.TCPFlowDirection) {
	if tcp == nil || !tcp.SYN || s.sshRoleConflict {
		return
	}
	client := sshHalfIndex(direction)
	evidence := events.SSHRoleEvidenceTCPSYN
	if tcp.ACK {
		client = 1 - client
		evidence = events.SSHRoleEvidenceTCPSYNACK
	}
	if s.sshRoleKnown && s.sshClientHalf != client {
		s.sshRoleConflict = true
		return
	}
	s.sshRoleKnown, s.sshClientHalf = true, client
	if s.sshRoleEvidence == "" || evidence == events.SSHRoleEvidenceTCPSYN {
		s.sshRoleEvidence = evidence
	}
}

func (p *sshIdentificationProbe) scan(data []byte, mark reassemblyMark) (int, bool) {
	if p.disabled {
		return 0, false
	}
	p.last = mark
	p.partial = p.partial || mark.ctx.partial
	p.filtered = p.filtered || mark.ctx.scope == events.CaptureScopeFiltered
	for offset, b := range data {
		p.scanned++
		if p.scanned > sshparser.MaxPreludeBytes+sshparser.MaxIdentificationBytes || p.lines > sshparser.MaxPreludeLines {
			p.disabled = true
			return 0, false
		}
		if p.lineBytes == p.matched && p.matched < len("SSH-") && b == "SSH-"[p.matched] {
			p.matched++
			p.lineBytes++
			if p.matched == len("SSH-") {
				return offset + 1, true
			}
			continue
		}
		p.lineBytes++
		p.matched = 0
		if p.lineBytes > sshparser.MaxIdentificationBytes {
			p.disabled = true
			return 0, false
		}
		if b == '\n' {
			p.lineBytes = 0
			p.lines++
		}
	}
	return 0, false
}

func (s *applicationStream) admitSSH() bool {
	policy := s.runtime.cfg.Policy.EffectiveSSH()
	stats := &s.runtime.stats.SSH
	if stats.ActiveFlows >= policy.MaxFlows || sshFlowReservationBytes > policy.MaxBytes-stats.ReservedBytes {
		stats.Rejected++
		s.sshRejected = true
		return false
	}
	s.ssh = &sshConnection{}
	stats.ActiveFlows++
	stats.ReservedBytes += sshFlowReservationBytes
	stats.Admitted++
	// A protocol identification supersedes the generic prospective buffer.
	s.consume(len(s.buffer))
	for i := range s.ssh.halves {
		half, probe := &s.ssh.halves[i], &s.sshProbe[i]
		half.partial, half.filtered = probe.partial, probe.filtered
		if probe.gap {
			half.parser.Stop(sshparser.StopGap)
		} else if probe.matched != 0 && probe.matched < len("SSH-") {
			s.feedSSH(i, []byte("SSH-"[:probe.matched]), probe.last)
		}
	}
	return true
}

func (s *applicationStream) reassembleSSH(sg reassembly.ScatterGather, skip int) bool {
	if !s.runtime.cfg.Policy.EffectiveSSH().Enabled {
		return false
	}
	if s.sshRejected {
		return true
	}
	direction, _, _, _ := sg.Info()
	index := sshHalfIndex(direction)
	if skip > 0 {
		s.sshProbe[index].disabled, s.sshProbe[index].gap = true, true
	}
	available, _ := sg.Lengths()
	chunk := sg.Fetch(available)
	if s.ssh == nil {
		if s.framedProtocol == "" {
			// Inspect only the bounded first-line prefix. A valid HTTP start
			// line owns its following headers/body before the complete request
			// can be emitted, including coalesced and segmented messages. Port
			// numbers and unvalidated packet hints cannot claim this boundary.
			var prefix [8193]byte
			n := copy(prefix[:], s.buffer)
			n += copy(prefix[n:], chunk)
			if httpparser.NewParser().RecognizesPayload(prefix[:n]) {
				s.framedProtocol = "http"
			}
		}
		if s.framedProtocol != "" {
			return false
		}
	}
	start := 0
	reassembly.ForEachCaptureInfo(sg, func(end int, ci gopacket.CaptureInfo) {
		if end <= start || end > len(chunk) {
			return
		}
		data := chunk[start:end]
		start = end
		ctx, ok := captureContext(ci)
		if !ok {
			return
		}
		mark := reassemblyMark{ctx: ctx, ci: ci}
		if skip != 0 {
			mark.ctx.partial = true
		}
		if s.ssh == nil {
			offset, recognized := s.sshProbe[index].scan(data, mark)
			if !recognized || !s.admitSSH() {
				return
			}
			s.feedSSH(index, []byte("SSH-"), mark)
			data = data[offset:]
		}
		if skip > 0 {
			half := &s.ssh.halves[index]
			if !half.parser.Stopped() {
				half.parser.Stop(sshparser.StopGap)
			}
			half.last, half.observed, half.partial = mark, true, true
			s.emitSSHTerminal(index, nil)
			return
		}
		s.feedSSH(index, data, mark)
	})
	return s.ssh != nil || s.sshRejected
}

func (s *applicationStream) feedSSH(index int, payload []byte, mark reassemblyMark) {
	half := &s.ssh.halves[index]
	if len(payload) == 0 || half.terminal {
		return
	}
	half.last, half.observed = mark, true
	half.partial = half.partial || mark.ctx.partial
	half.filtered = half.filtered || mark.ctx.scope == events.CaptureScopeFiltered
	if half.parser.Stopped() {
		s.emitSSHTerminal(index, nil)
		return
	}
	err := half.parser.Feed(payload, func(observation sshparser.Observation) {
		if observation.Identification != nil {
			half.identification = observation.Identification
			s.emitSSH(index, events.SSHStatusBanner, events.SSHReasonNone, nil)
		}
		if observation.KEXINIT != nil {
			s.emitSSHTerminal(index, observation.KEXINIT)
		}
	})
	if err != nil {
		s.runtime.stats.Invalid++
	}
	if half.parser.Stopped() && !half.terminal {
		s.emitSSHTerminal(index, nil)
	}
}

func (s *applicationStream) emitSSHTerminal(index int, kex *sshparser.KEXINIT) {
	half := &s.ssh.halves[index]
	if half.terminal || !half.observed {
		return
	}
	half.terminal = true
	status := events.SSHStatusPartial
	if kex != nil && half.parser.StopReason() == sshparser.StopKEXComplete {
		status = events.SSHStatusComplete
	}
	s.emitSSH(index, status, events.SSHReason(half.parser.StopReason()), kex)
}

func escapedSSHBanner(raw string) (string, bool) {
	if !utf8.ValidString(raw) {
		return strconv.QuoteToASCII(raw), true
	}
	for _, r := range raw {
		if !unicode.IsPrint(r) {
			return strconv.QuoteToASCII(raw), true
		}
	}
	return raw, false
}

func (s *applicationStream) emitSSH(index int, status events.SSHStatus, reason events.SSHReason, kex *sshparser.KEXINIT) {
	half := &s.ssh.halves[index]
	mark := half.last
	metadata := &data.PacketMetadata{SrcIp: mark.ctx.netFlow.Src().String(), DstIp: mark.ctx.netFlow.Dst().String(), SrcPort: uint32(flowPort(mark.ctx.tcpFlow.Src())), DstPort: uint32(flowPort(mark.ctx.tcpFlow.Dst())), Transport: "tcp", Protocol: "SSH"}
	scope := mark.ctx.scope
	if scope == "" {
		scope = events.CaptureScopeFull
	}
	if half.filtered {
		scope = events.CaptureScopeFiltered
	}
	env, err := s.runtime.envelope(mark.ctx.source, metadata, mark.ci.Timestamp, scope, half.partial || status == events.SSHStatusPartial)
	if err != nil {
		s.runtime.stats.Invalid++
		return
	}
	event := events.NewSSHEvent(env)
	event.Status, event.Reason = status, reason
	if s.sshRoleConflict {
		event.RoleEvidence = events.SSHRoleEvidenceConflict
	} else if s.sshRoleKnown {
		event.Role, event.RoleEvidence = events.SSHRoleServer, s.sshRoleEvidence
		if index == s.sshClientHalf {
			event.Role = events.SSHRoleClient
		}
	}
	if identification := half.identification; identification != nil {
		event.Banner, event.BannerEscaped = escapedSSHBanner(identification.Banner)
		event.ProtocolVersion, event.SoftwareVersion = identification.ProtocolVersion, identification.SoftwareVersion
		// A validated identification is positive service evidence. The existing
		// inventory tracker deliberately supports its own separate proof set;
		// this call labels the connection without extending that policy.
		if err := s.runtime.connections.SetAnalyzedService(env, s.runtime.associationScope(mark.ctx.source, env), "SSH", false); err != nil {
			s.runtime.stats.Invalid++
		}
	}
	if kex != nil {
		event.KEXAlgorithms, event.ServerHostKeyAlgorithms = kex.KEXAlgorithms, kex.ServerHostKeyAlgorithms
		event.EncryptionClientServer, event.EncryptionServerClient = kex.EncryptionClientServer, kex.EncryptionServerClient
		event.MACClientServer, event.MACServerClient = kex.MACClientServer, kex.MACServerClient
		event.CompressionClientServer, event.CompressionServerClient = kex.CompressionClientServer, kex.CompressionServerClient
		event.LanguagesClientServer, event.LanguagesServerClient = kex.LanguagesClientServer, kex.LanguagesServerClient
		event.FirstKEXPacketFollows = kex.FirstKEXPacketFollows
		if fingerprint, available := kex.Fingerprint(sshparser.Role(event.Role)); available {
			event.HASSH, event.HASSHAlgorithms, event.HASSHVersion = fingerprint.Hash, fingerprint.Algorithms, fingerprint.Version
		}
	}
	if status == events.SSHStatusBanner {
		s.runtime.stats.SSH.Banners++
	} else if status == events.SSHStatusComplete {
		s.runtime.stats.SSH.Complete++
	} else {
		s.runtime.stats.SSH.Partial++
	}
	s.runtime.emit(event)
}

func (s *applicationStream) closeSSH() {
	if s.ssh == nil {
		return
	}
	for index := range s.ssh.halves {
		half := &s.ssh.halves[index]
		if half.observed && !half.terminal {
			half.parser.End()
			s.emitSSHTerminal(index, nil)
		}
	}
	s.runtime.stats.SSH.ActiveFlows--
	s.runtime.stats.SSH.ReservedBytes -= sshFlowReservationBytes
	s.ssh = nil
}
