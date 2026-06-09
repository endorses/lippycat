// Package capture provides network packet capture functionality.
// This file contains a custom IPv6 datagram defragmenter.
//
// gopacket ships ip4defrag but no IPv6 equivalent. A fragmented IPv6
// datagram therefore arrives with its transport header (UDP/TCP) stranded
// behind the Fragment extension header: gopacket leaves the payload
// undecoded, TransportLayer() returns nil, and the packet is dropped.
//
// This is critical for VoIP: large SIP INVITEs routinely fragment over
// IPv6 on IMS/VXLAN tunnels. Without reassembly the call surfaces with
// neither INVITE nor SDP, so RTP ports are never registered and every
// audio packet ends up unmatched ("RTP-only" calls).
//
// ESP-encapsulated IPv6 fragments are handled separately by
// decapsulateIPv6FragmentESP; callers route only non-ESP fragments here.
package capture

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Fragment bounds per RFC 8200 §4.5.
const (
	// IPv6MaximumPayloadSize bounds a reassembled datagram. The IPv6
	// payload length field is 16 bits; jumbograms are out of scope.
	IPv6MaximumPayloadSize = 65535

	// IPv6MaximumFragmentOffset is the largest fragment offset value
	// (13-bit field, expressed in 8-byte units).
	IPv6MaximumFragmentOffset = 8191

	// IPv6MaximumFragmentListLen caps fragments per flow (DoS protection).
	IPv6MaximumFragmentListLen = 8192
)

// IPv6Defragmenter reassembles fragmented IPv6 datagrams. State is keyed by
// (source IP, destination IP, fragment identification) per RFC 8200 §4.5.
//
// Scope is deliberately small: in-memory, bounded, TTL eviction. Losing the
// occasional reassembly under load is acceptable; corrupting state is not.
type IPv6Defragmenter struct {
	mu      sync.Mutex
	ipFlows map[ipv6FlowKey]*ipv6FragmentList
}

// NewIPv6Defragmenter creates a defragmenter with an initialized flow map.
func NewIPv6Defragmenter() *IPv6Defragmenter {
	return &IPv6Defragmenter{
		ipFlows: make(map[ipv6FlowKey]*ipv6FragmentList),
	}
}

// ipv6FlowKey uniquely identifies a fragmented IPv6 datagram.
type ipv6FlowKey struct {
	flow gopacket.Flow // src/dst IP pair
	id   uint32        // Fragment header Identification field
}

// ipv6Fragment is one received fragment, copied out of the capture buffer.
type ipv6Fragment struct {
	offset uint16 // byte offset from the start of the reassembled payload
	data   []byte
}

// ipv6FragmentList accumulates the fragments of a single datagram.
type ipv6FragmentList struct {
	pieces        []ipv6Fragment
	nextHeader    layers.IPProtocol // inner protocol (same in every fragment header)
	highest       int               // highest offset+len seen
	current       int               // total payload bytes received
	totalLen      int               // -1 until the final fragment (M=0) arrives
	finalReceived bool
	lastSeen      time.Time
}

// DefragIPv6 attempts to reassemble one IPv6 fragment.
//
// Returns:
//   - (*layers.IPv6, nil) — reassembled datagram once all fragments arrived
//   - (nil, nil)          — fragment stored, waiting for more
//   - (nil, error)        — fragment rejected (malformed or DoS guard)
func (d *IPv6Defragmenter) DefragIPv6(ip6 *layers.IPv6, frag *layers.IPv6Fragment) (*layers.IPv6, error) {
	return d.DefragIPv6WithTimestamp(ip6, frag, time.Now())
}

// DefragIPv6WithTimestamp is like DefragIPv6 but uses the provided
// timestamp for TTL decisions — useful when replaying PCAP files.
func (d *IPv6Defragmenter) DefragIPv6WithTimestamp(ip6 *layers.IPv6, frag *layers.IPv6Fragment, t time.Time) (*layers.IPv6, error) {
	if ip6 == nil || frag == nil {
		return nil, errors.New("defrag6: nil IPv6 or fragment layer")
	}

	if frag.FragmentOffset > IPv6MaximumFragmentOffset {
		return nil, fmt.Errorf("defrag6: fragment offset too large (%d > %d)",
			frag.FragmentOffset, IPv6MaximumFragmentOffset)
	}

	payload := frag.LayerPayload()
	if len(payload) == 0 {
		return nil, errors.New("defrag6: empty fragment payload")
	}

	offsetBytes := int(frag.FragmentOffset) * 8
	if offsetBytes+len(payload) > IPv6MaximumPayloadSize {
		return nil, fmt.Errorf("defrag6: fragment would exceed maximum IPv6 payload size (%d > %d)",
			offsetBytes+len(payload), IPv6MaximumPayloadSize)
	}

	// Non-final fragments must be a multiple of 8 bytes — the offset field
	// is in 8-byte units, so a non-aligned non-final fragment is malformed.
	if frag.MoreFragments && len(payload)%8 != 0 {
		return nil, errors.New("defrag6: non-final fragment not a multiple of 8 bytes")
	}

	key := ipv6FlowKey{flow: ip6.NetworkFlow(), id: frag.Identification}

	d.mu.Lock()
	defer d.mu.Unlock()

	fl, exists := d.ipFlows[key]
	if !exists {
		fl = &ipv6FragmentList{totalLen: -1}
		d.ipFlows[key] = fl
	}

	// DoS guard: bound fragments per flow.
	if len(fl.pieces)+1 > IPv6MaximumFragmentListLen {
		delete(d.ipFlows, key)
		return nil, fmt.Errorf("defrag6: fragment list exceeded maximum size (%d)",
			IPv6MaximumFragmentListLen)
	}

	// Copy the fragment bytes out: the capture buffer may be reused before
	// reassembly completes.
	dup := make([]byte, len(payload))
	copy(dup, payload)
	fl.pieces = append(fl.pieces, ipv6Fragment{offset: uint16(offsetBytes), data: dup})
	fl.current += len(dup)
	fl.nextHeader = frag.NextHeader // identical across every fragment header
	fl.lastSeen = t
	if end := offsetBytes + len(dup); end > fl.highest {
		fl.highest = end
	}
	if !frag.MoreFragments {
		fl.finalReceived = true
		fl.totalLen = offsetBytes + len(dup)
	}

	// Not done until the final fragment has arrived and every byte is in.
	if !fl.finalReceived || fl.current != fl.totalLen {
		return nil, nil
	}

	out, err := fl.build(ip6)
	delete(d.ipFlows, key)
	return out, err
}

// DiscardOlderThan removes fragment lists not updated since time t and
// returns the number discarded. Call periodically to bound memory use.
func (d *IPv6Defragmenter) DiscardOlderThan(t time.Time) int {
	var count int
	d.mu.Lock()
	for key, fl := range d.ipFlows {
		if fl.lastSeen.Before(t) {
			delete(d.ipFlows, key)
			count++
		}
	}
	d.mu.Unlock()
	return count
}

// inFlight reports how many incomplete datagrams are buffered.
// Exposed for tests and diagnostics.
func (d *IPv6Defragmenter) inFlight() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.ipFlows)
}

// build stitches the fragments into a complete IPv6 layer. It sorts by
// offset and verifies the pieces are contiguous (no gaps, no overlaps);
// anything else is rejected rather than producing a corrupt datagram.
func (fl *ipv6FragmentList) build(ip6 *layers.IPv6) (*layers.IPv6, error) {
	sort.Slice(fl.pieces, func(i, j int) bool {
		return fl.pieces[i].offset < fl.pieces[j].offset
	})

	payload := make([]byte, 0, fl.totalLen)
	var expect uint16
	for _, p := range fl.pieces {
		if p.offset != expect {
			return nil, errors.New("defrag6: hole or overlap in fragment sequence")
		}
		payload = append(payload, p.data...)
		expect = p.offset + uint16(len(p.data))
	}

	// Reassembled datagram: Fragment extension header dropped, NextHeader
	// set to the inner protocol. Length is recomputed on serialization.
	out := &layers.IPv6{
		Version:      ip6.Version,
		TrafficClass: ip6.TrafficClass,
		FlowLabel:    ip6.FlowLabel,
		Length:       uint16(len(payload)),
		NextHeader:   fl.nextHeader,
		HopLimit:     ip6.HopLimit,
		SrcIP:        ip6.SrcIP,
		DstIP:        ip6.DstIP,
	}
	out.Payload = payload
	return out, nil
}

// rebuildReassembledIPv6Packet produces a complete gopacket.Packet from a
// reassembled IPv6 layer, so downstream decoding sees an intact transport
// layer. It is the IPv6 analogue of rebuildReassembledPacket and preserves
// the original Ethernet/VLAN framing and capture metadata.
func rebuildReassembledIPv6Packet(original gopacket.Packet, reassembledIP *layers.IPv6, linkType layers.LinkType) gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var ethLayer *layers.Ethernet
	if eth := original.Layer(layers.LayerTypeEthernet); eth != nil {
		ethLayer = eth.(*layers.Ethernet)
	}

	// Preserve a VLAN tag if present — it sits between Ethernet and IP.
	var dot1qLayer *layers.Dot1Q
	if dot1q := original.Layer(layers.LayerTypeDot1Q); dot1q != nil {
		dot1qLayer = dot1q.(*layers.Dot1Q)
	}

	var err error
	switch {
	case ethLayer != nil && dot1qLayer != nil:
		err = gopacket.SerializeLayers(buf, opts,
			ethLayer, dot1qLayer, reassembledIP,
			gopacket.Payload(reassembledIP.Payload))
	case ethLayer != nil:
		err = gopacket.SerializeLayers(buf, opts,
			ethLayer, reassembledIP,
			gopacket.Payload(reassembledIP.Payload))
	default:
		// No Ethernet layer (loopback or raw IP capture).
		err = gopacket.SerializeLayers(buf, opts,
			reassembledIP,
			gopacket.Payload(reassembledIP.Payload))
	}

	if err != nil {
		logger.Debug("Failed to serialize reassembled IPv6 packet", "error", err)
		return original // incomplete, but better than dropping outright
	}

	newPacket := gopacket.NewPacket(buf.Bytes(), linkType, gopacket.Default)

	// Preserve original capture metadata (timestamp, lengths).
	if original.Metadata() != nil {
		newMeta := newPacket.Metadata()
		newMeta.Timestamp = original.Metadata().Timestamp
		newMeta.CaptureLength = len(buf.Bytes())
		newMeta.Length = len(buf.Bytes())
	}

	return newPacket
}
