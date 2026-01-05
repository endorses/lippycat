package voip

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CallBuffer holds packets for a call until filter decision is made
type CallBuffer struct {
	callID        string
	sipPackets    []gopacket.Packet // Buffered SIP packets
	rtpPackets    []gopacket.Packet // Buffered RTP packets
	metadata      *CallMetadata     // Extracted SIP headers
	filterChecked bool              // Whether filter match was evaluated
	matched       bool              // Whether call matches filter
	createdAt     time.Time
	rtpPorts      []string        // RTP ports for this call
	interfaceName string          // Interface where packets were captured
	linkType      layers.LinkType // Link type for PCAP writing (e.g., Ethernet, Linux cooked, raw IP)
}

// CallMetadata contains extracted SIP header information
type CallMetadata struct {
	From              string
	To                string
	FromTag           string // SIP From tag parameter (for dialog correlation)
	ToTag             string // SIP To tag parameter (for dialog correlation)
	PAssertedIdentity string
	CallID            string
	Method            string
	ResponseCode      uint32 // SIP response code (e.g., 200, 180, 486)
	SDPBody           string // For RTP port extraction
}

// NewCallBuffer creates a new call buffer
func NewCallBuffer(callID string) *CallBuffer {
	return &CallBuffer{
		callID:     callID,
		sipPackets: make([]gopacket.Packet, 0, 10),
		rtpPackets: make([]gopacket.Packet, 0, 100),
		createdAt:  time.Now(),
		rtpPorts:   make([]string, 0, 2),
	}
}

// AddSIPPacket adds a SIP packet to the buffer
func (cb *CallBuffer) AddSIPPacket(packet gopacket.Packet) {
	cb.sipPackets = append(cb.sipPackets, packet)
}

// AddRTPPacket adds an RTP packet to the buffer
func (cb *CallBuffer) AddRTPPacket(packet gopacket.Packet) {
	cb.rtpPackets = append(cb.rtpPackets, packet)
}

// GetAllPackets returns all buffered packets (SIP + RTP) in chronological order
func (cb *CallBuffer) GetAllPackets() []gopacket.Packet {
	all := make([]gopacket.Packet, 0, len(cb.sipPackets)+len(cb.rtpPackets))
	all = append(all, cb.sipPackets...)
	all = append(all, cb.rtpPackets...)
	return all
}

// IsRTPPort checks if a port belongs to this call's RTP stream
func (cb *CallBuffer) IsRTPPort(port string) bool {
	for _, p := range cb.rtpPorts {
		if p == port {
			return true
		}
	}
	return false
}

// AddRTPPort adds an RTP port to the call's port list
func (cb *CallBuffer) AddRTPPort(port string) {
	// Avoid duplicates
	if !cb.IsRTPPort(port) {
		cb.rtpPorts = append(cb.rtpPorts, port)
	}
}

// GetCallID returns the call ID
func (cb *CallBuffer) GetCallID() string {
	return cb.callID
}

// GetMetadata returns the call metadata
func (cb *CallBuffer) GetMetadata() *CallMetadata {
	return cb.metadata
}

// SetMetadata sets the call metadata
func (cb *CallBuffer) SetMetadata(metadata *CallMetadata) {
	cb.metadata = metadata
}

// IsFilterChecked returns whether filter has been evaluated
func (cb *CallBuffer) IsFilterChecked() bool {
	return cb.filterChecked
}

// IsMatched returns whether call matched the filter
func (cb *CallBuffer) IsMatched() bool {
	return cb.matched
}

// SetFilterResult sets the filter evaluation result
func (cb *CallBuffer) SetFilterResult(matched bool) {
	cb.filterChecked = true
	cb.matched = matched
}

// GetAge returns the age of the buffer
func (cb *CallBuffer) GetAge() time.Duration {
	return time.Since(cb.createdAt)
}

// GetPacketCount returns the total number of buffered packets
func (cb *CallBuffer) GetPacketCount() int {
	return len(cb.sipPackets) + len(cb.rtpPackets)
}

// SetInterfaceName sets the interface name for this call's packets
func (cb *CallBuffer) SetInterfaceName(name string) {
	cb.interfaceName = name
}

// GetInterfaceName returns the interface name for this call's packets
func (cb *CallBuffer) GetInterfaceName() string {
	return cb.interfaceName
}

// SetLinkType sets the link type for this call's packets
func (cb *CallBuffer) SetLinkType(linkType layers.LinkType) {
	cb.linkType = linkType
}

// GetLinkType returns the link type for this call's packets
func (cb *CallBuffer) GetLinkType() layers.LinkType {
	return cb.linkType
}
