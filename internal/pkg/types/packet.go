package types

import (
	"time"

	"github.com/endorses/lippycat/api/gen/management"
)

// PacketDisplay represents a packet for display purposes.
// This type is shared between capture, remote capture, and TUI components.
type PacketDisplay struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Protocol  string
	Length    int
	Info      string
	RawData   []byte        // Raw packet bytes for hex dump
	NodeID    string        // Source node identifier: "Local", hunter_id, or processor_id
	Interface string        // Network interface where packet was captured
	VoIPData  *VoIPMetadata // Parsed VoIP metadata (nil if not VoIP)
}

// VoIPMetadata contains parsed VoIP protocol information.
type VoIPMetadata struct {
	// SIP fields
	CallID      string
	Method      string            // SIP method (INVITE, ACK, etc.)
	Status      int               // SIP response code
	From        string            // SIP From header
	To          string            // SIP To header
	User        string            // Username from URI
	ContentType string            // Content-Type header
	Headers     map[string]string // All SIP headers

	// RTP fields
	IsRTP       bool   // Whether this is an RTP packet
	SSRC        uint32 // RTP SSRC
	PayloadType uint8  // RTP payload type
	SequenceNum uint16 // RTP sequence number
	SeqNumber   uint16 // Alias for SequenceNum (for compatibility)
	Timestamp   uint32 // RTP timestamp
	Codec       string // RTP codec (if applicable)
}

// HunterInfo represents a hunter node's status information.
// This type is shared between processor, remote capture client, and TUI.
type HunterInfo struct {
	ID               string
	Hostname         string
	RemoteAddr       string
	Status           management.HunterStatus
	ConnectedAt      int64
	LastHeartbeat    int64
	PacketsCaptured  uint64
	PacketsMatched   uint64
	PacketsForwarded uint64
	PacketsDropped   uint64
	ActiveFilters    uint32
	Interfaces       []string
	ProcessorAddr    string // Address of processor this hunter belongs to
}
