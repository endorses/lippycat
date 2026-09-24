// Package capture provides network packet capture functionality.
// This file contains a custom IPv4 defragmenter based on gopacket's ip4defrag
// with RFC 791-compliant handling of small final fragments.
//
// gopacket's ip4defrag incorrectly rejects final fragments smaller than 8 bytes.
// Per RFC 791, only intermediate fragments (MF=1) must be multiples of 8 bytes.
// Final fragments (MF=0, offset > 0) can be any size, including 1-7 bytes.
//
// This is critical for VoIP because large SIP INVITEs can fragment such that
// the final fragment (containing the tail end of SDP with media ports) is
// smaller than 8 bytes. Without this fix, those fragments are rejected and
// RTP correlation fails, creating "RTP-only" calls.
package capture

import (
	"container/heap"
	"container/list"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Fragment size and offset constants per RFC 791
const (
	// IPv4MinimumFragmentSize is the minimum size for non-final fragments.
	// Per RFC 791, fragment offset is in 8-octet units, so intermediate
	// fragments must be multiples of 8 bytes. Final fragments can be any size.
	IPv4MinimumFragmentSize = 8

	// IPv4MaximumSize is the maximum size of an IPv4 packet (2^16 - 1)
	IPv4MaximumSize = 65535

	// IPv4MaximumFragmentOffset is the maximum fragment offset value
	// (13 bits = 8191, in 8-byte units = 65528 bytes)
	IPv4MaximumFragmentOffset = 8191

	// IPv4MaximumFragmentListLen limits fragments per flow to prevent DoS
	IPv4MaximumFragmentListLen = 8192
)

// IPv4DefragConfig bounds incomplete datagrams retained by one capture session.
// Zero values select defaults; negative values are invalid.
type IPv4DefragConfig struct {
	MaxDatagrams            int
	MaxFragments            int
	MaxPayloadBytes         int
	MaxFragmentsPerDatagram int
	StaleAge                time.Duration
	SweepInterval           time.Duration
}

func (c IPv4DefragConfig) Resolve() (IPv4DefragConfig, error) {
	if c.MaxDatagrams < 0 || c.MaxFragments < 0 || c.MaxPayloadBytes < 0 || c.MaxFragmentsPerDatagram < 0 || c.StaleAge < 0 || c.SweepInterval < 0 {
		return c, errors.New("IPv4 defragmentation limits must be non-negative")
	}
	if c.MaxDatagrams == 0 {
		c.MaxDatagrams = 4096
	}
	if c.MaxFragments == 0 {
		c.MaxFragments = 16384
	}
	if c.MaxPayloadBytes == 0 {
		c.MaxPayloadBytes = 16 << 20
	}
	if c.MaxFragmentsPerDatagram == 0 {
		c.MaxFragmentsPerDatagram = 128
	}
	if c.StaleAge == 0 {
		c.StaleAge = 30 * time.Second
	}
	if c.SweepInterval == 0 {
		c.SweepInterval = 5 * time.Second
	}
	if c.MaxFragmentsPerDatagram > IPv4MaximumFragmentListLen || c.MaxFragmentsPerDatagram > c.MaxFragments || c.MaxDatagrams > c.MaxFragments || c.MaxPayloadBytes < IPv4MinimumFragmentSize {
		return c, errors.New("inconsistent IPv4 defragmentation limits")
	}
	return c, nil
}

// IPv4DefragSnapshot is cumulative for one defragmenter, except InFlight fields.
// Rejected counts invalid input and fragments that cannot fit even after eviction.
type IPv4DefragSnapshot struct {
	ObservedFragments    uint64
	CompletedDatagrams   uint64
	RejectedFragments    uint64
	ExpiredDatagrams     uint64
	CapacityEvictions    uint64
	InFlightDatagrams    int
	InFlightFragments    int
	InFlightPayloadBytes int
}

// IPv4Defragmenter reassembles fragmented IPv4 packets.
// It maintains state for multiple concurrent flows identified by
// (source IP, destination IP, protocol, fragment ID).
type IPv4Defragmenter struct {
	mu         sync.Mutex
	ipFlows    map[ipv4FlowKey]*fragmentList
	oldest     flowHeap
	config     IPv4DefragConfig
	stats      IPv4DefragSnapshot
	nextSerial uint64
}

// NewIPv4Defragmenter creates a new defragmenter with an initialized flow map.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	d, _ := NewIPv4DefragmenterWithConfig(IPv4DefragConfig{})
	return d
}

func NewIPv4DefragmenterWithConfig(config IPv4DefragConfig) (*IPv4Defragmenter, error) {
	resolved, err := config.Resolve()
	if err != nil {
		return nil, err
	}
	return &IPv4Defragmenter{
		ipFlows: make(map[ipv4FlowKey]*fragmentList),
		config:  resolved,
	}, nil
}

func (d *IPv4Defragmenter) Snapshot() IPv4DefragSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.stats
	s.InFlightDatagrams = len(d.ipFlows)
	return s
}

// ipv4FlowKey uniquely identifies a fragmented packet flow
type ipv4FlowKey struct {
	flow     gopacket.Flow // src/dst IP pair
	id       uint16        // IP identification field
	protocol layers.IPProtocol
}

// fragmentList holds fragments for a single IP packet being reassembled
type fragmentList struct {
	List          list.List // Ordered list of fragments
	Highest       uint16    // Highest byte offset seen (offset + length)
	FinalReceived bool      // True when last fragment (MF=0) received
	LastSeen      time.Time // For cleanup of stale fragments
	key           ipv4FlowKey
	heapIndex     int
	payloadBytes  int
	finalEnd      uint16
	serial        uint64
}

type flowHeap []*fragmentList

func (h flowHeap) Len() int { return len(h) }
func (h flowHeap) Less(i, j int) bool {
	if h[i].LastSeen.Equal(h[j].LastSeen) {
		return h[i].serial < h[j].serial
	}
	return h[i].LastSeen.Before(h[j].LastSeen)
}
func (h flowHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i]; h[i].heapIndex = i; h[j].heapIndex = j }
func (h *flowHeap) Push(x any)   { fl := x.(*fragmentList); fl.heapIndex = len(*h); *h = append(*h, fl) }
func (h *flowHeap) Pop() any {
	old := *h
	fl := old[len(old)-1]
	*h = old[:len(old)-1]
	fl.heapIndex = -1
	return fl
}

// removeLocked removes only the flow instance that was inspected.
func (d *IPv4Defragmenter) removeLocked(fl *fragmentList) bool {
	if d.ipFlows[fl.key] != fl {
		return false
	}
	delete(d.ipFlows, fl.key)
	heap.Remove(&d.oldest, fl.heapIndex)
	d.stats.InFlightFragments -= fl.List.Len()
	d.stats.InFlightPayloadBytes -= fl.payloadBytes
	return true
}

// DefragIPv4 attempts to reassemble an IPv4 fragment.
//
// Returns:
//   - (*layers.IPv4, nil) - Reassembled packet when all fragments received
//   - (in, nil) - Original packet if not fragmented
//   - (nil, nil) - Fragment stored, waiting for more fragments
//   - (nil, error) - Fragment rejected due to security checks
func (d *IPv4Defragmenter) DefragIPv4(in *layers.IPv4) (*layers.IPv4, error) {
	return d.DefragIPv4WithTimestamp(in, time.Now())
}

// DefragIPv4WithTimestamp is like DefragIPv4 but uses the provided timestamp
// instead of time.Now(). Useful for processing PCAP files where packet
// timestamps should be used for fragment timeout decisions.
func (d *IPv4Defragmenter) DefragIPv4WithTimestamp(in *layers.IPv4, t time.Time) (*layers.IPv4, error) {
	// Check if packet needs defragmentation
	if d.dontDefrag(in) {
		return in, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.stats.ObservedFragments++
	if err := d.securityChecks(in); err != nil {
		d.stats.RejectedFragments++
		return nil, err
	}

	// Create flow key for this fragment
	key := ipv4FlowKey{
		flow:     in.NetworkFlow(),
		id:       in.Id,
		protocol: in.Protocol,
	}

	fl, exists := d.ipFlows[key]
	for e := flFront(fl); e != nil; e = e.Next() {
		if e.Value.(*layers.IPv4).FragOffset == in.FragOffset {
			return nil, nil
		}
	}
	fragBytes := len(in.Payload)
	if fragBytes > d.config.MaxPayloadBytes {
		d.stats.RejectedFragments++
		return nil, fmt.Errorf("defrag: fragment exceeds retained payload limit (%d)", d.config.MaxPayloadBytes)
	}
	if exists && fl.List.Len() >= d.config.MaxFragmentsPerDatagram {
		d.stats.RejectedFragments++
		return nil, fmt.Errorf("defrag: fragment list exceeded maximum size (%d)", d.config.MaxFragmentsPerDatagram)
	}
	// No other eviction can make this fragment fit while preserving its own
	// incomplete datagram. Reject before discarding unrelated flows.
	if exists && (fl.List.Len() >= d.config.MaxFragments || fragBytes > d.config.MaxPayloadBytes-fl.payloadBytes) {
		d.stats.RejectedFragments++
		return nil, errors.New("defrag: protected datagram exceeds capacity")
	}
	for len(d.ipFlows)+boolInt(!exists) > d.config.MaxDatagrams || d.stats.InFlightFragments+1 > d.config.MaxFragments || d.stats.InFlightPayloadBytes+fragBytes > d.config.MaxPayloadBytes {
		victim := d.oldestExceptLocked(fl)
		if victim == nil {
			break
		}
		if d.removeLocked(victim) {
			d.stats.CapacityEvictions++
		}
	}
	if len(d.ipFlows)+boolInt(!exists) > d.config.MaxDatagrams || d.stats.InFlightFragments+1 > d.config.MaxFragments || d.stats.InFlightPayloadBytes+fragBytes > d.config.MaxPayloadBytes {
		d.stats.RejectedFragments++
		return nil, errors.New("defrag: capacity exhausted")
	}
	if !exists {
		d.nextSerial++
		fl = &fragmentList{key: key, LastSeen: t, serial: d.nextSerial}
		d.ipFlows[key] = fl
		heap.Push(&d.oldest, fl)
	}
	d.stats.InFlightFragments++
	d.stats.InFlightPayloadBytes += fragBytes
	fl.payloadBytes += fragBytes
	out, err := fl.insert(in)
	if err != nil {
		d.stats.RejectedFragments++
		d.removeLocked(fl)
		return nil, err
	}
	if t.After(fl.LastSeen) {
		fl.LastSeen = t
		heap.Fix(&d.oldest, fl.heapIndex)
	}
	if out != nil {
		d.stats.CompletedDatagrams++
		d.removeLocked(fl)
	}
	return out, nil
}

// The second-oldest flow is one of the root's children in a min-heap.
// This preserves an existing incoming datagram without scanning all flows.
func (d *IPv4Defragmenter) oldestExceptLocked(protected *fragmentList) *fragmentList {
	if len(d.oldest) == 0 {
		return nil
	}
	if d.oldest[0] != protected {
		return d.oldest[0]
	}
	if len(d.oldest) == 1 {
		return nil
	}
	index := 1
	if len(d.oldest) > 2 && d.oldest.Less(2, 1) {
		index = 2
	}
	return d.oldest[index]
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func flFront(fl *fragmentList) *list.Element {
	if fl == nil {
		return nil
	}
	return fl.List.Front()
}

// DiscardOlderThan removes all fragment lists that haven't been updated
// since time t. Returns the number of flows discarded.
// This should be called periodically to prevent memory leaks from
// incomplete fragment sequences.
func (d *IPv4Defragmenter) DiscardOlderThan(t time.Time) int {
	var count int
	d.mu.Lock()
	for len(d.oldest) > 0 && d.oldest[0].LastSeen.Before(t) {
		if d.removeLocked(d.oldest[0]) {
			count++
			d.stats.ExpiredDatagrams++
		}
	}
	d.mu.Unlock()
	return count
}

// dontDefrag returns true if the packet doesn't need defragmentation
func (d *IPv4Defragmenter) dontDefrag(ip *layers.IPv4) bool {
	// Don't defrag packets with DF (Don't Fragment) flag
	if ip.Flags&layers.IPv4DontFragment != 0 {
		return true
	}
	// Don't defrag non-fragmented packets (MF=0 and offset=0)
	if ip.Flags&layers.IPv4MoreFragments == 0 && ip.FragOffset == 0 {
		return true
	}
	return false
}

// securityChecks validates fragment parameters to prevent malicious packets.
//
// RFC 791 COMPLIANCE FIX:
// gopacket's original implementation incorrectly rejects ALL fragments smaller
// than 8 bytes. Per RFC 791, only intermediate fragments (MF=1) must be
// multiples of 8 bytes because the fragment offset field is in 8-byte units.
// Final fragments (MF=0 with offset > 0) can be any size.
//
// This is critical for SIP/VoIP where large INVITEs can fragment such that
// the final piece is 1-7 bytes (e.g., "13\r\n\r\n" = 7 bytes).
func (d *IPv4Defragmenter) securityChecks(ip *layers.IPv4) error {
	if ip.IHL < 5 || ip.Length < uint16(ip.IHL)*4 {
		return errors.New("defrag: invalid IPv4 fragment length")
	}
	// Calculate fragment payload size (total length - IP header length)
	fragSize := ip.Length - uint16(ip.IHL)*4

	// Determine if this is the final fragment (MF=0 means no more fragments)
	isFinalFragment := ip.Flags&layers.IPv4MoreFragments == 0

	// RFC 791 compliance: only enforce 8-byte minimum for non-final fragments
	// Final fragments can be any size (1-7 bytes is valid)
	if !isFinalFragment && fragSize < IPv4MinimumFragmentSize {
		return fmt.Errorf("defrag: non-final fragment too small (%d < %d bytes)",
			fragSize, IPv4MinimumFragmentSize)
	}

	// Validate fragment offset is within bounds
	if ip.FragOffset > IPv4MaximumFragmentOffset {
		return fmt.Errorf("defrag: fragment offset too large (%d > %d)",
			ip.FragOffset, IPv4MaximumFragmentOffset)
	}

	// Convert offset to bytes (offset field is in 8-byte units)
	fragOffsetBytes := uint32(ip.FragOffset) * 8

	// Ensure reassembled packet won't exceed maximum IP size
	if fragOffsetBytes+uint32(ip.Length) > IPv4MaximumSize {
		return fmt.Errorf("defrag: fragment would exceed maximum IP size (%d > %d)",
			fragOffsetBytes+uint32(ip.Length), IPv4MaximumSize)
	}
	if int(fragSize) != len(ip.Payload) {
		return errors.New("defrag: invalid IPv4 fragment length")
	}

	return nil
}

// insert adds a fragment to the list and returns the reassembled packet
// if all fragments have been received.
func (fl *fragmentList) insert(in *layers.IPv4) (*layers.IPv4, error) {
	fragOffset := in.FragOffset * 8 // Convert to bytes

	// Insert fragment in offset order (BSD-Right strategy: latest first)
	// This handles overlapping and out-of-order fragments correctly
	if fragOffset >= fl.Highest {
		fl.List.PushBack(in)
	} else {
		inserted := false
		for e := fl.List.Front(); e != nil; e = e.Next() {
			frag := e.Value.(*layers.IPv4)
			if in.FragOffset == frag.FragOffset {
				// Duplicate fragment, ignore
				return nil, nil
			}
			if in.FragOffset < frag.FragOffset {
				fl.List.InsertBefore(in, e)
				inserted = true
				break
			}
		}
		if !inserted {
			fl.List.PushBack(in)
		}
	}

	// Calculate fragment payload length (IP length - IP header)
	fragLength := in.Length - uint16(in.IHL)*4

	// Update tracking counters
	if fl.Highest < fragOffset+fragLength {
		fl.Highest = fragOffset + fragLength
	}

	// Check if this is the final fragment
	if in.Flags&layers.IPv4MoreFragments == 0 {
		fl.FinalReceived = true
		fl.finalEnd = fragOffset + fragLength
	}

	// A complete datagram must cover every byte through the final fragment.
	if fl.FinalReceived {
		var covered uint16
		for e := fl.List.Front(); e != nil; e = e.Next() {
			frag := e.Value.(*layers.IPv4)
			start := frag.FragOffset * 8
			if start > covered {
				return nil, nil
			}
			end := start + uint16(len(frag.Payload))
			if end > covered {
				covered = end
			}
		}
		if covered == fl.finalEnd {
			return fl.build(in)
		}
	}

	return nil, nil
}

// build reassembles fragments into a complete IPv4 packet
func (fl *fragmentList) build(in *layers.IPv4) (*layers.IPv4, error) {
	var payload []byte
	var currentOffset uint16

	for e := fl.List.Front(); e != nil; e = e.Next() {
		frag := e.Value.(*layers.IPv4)
		fragOffset := frag.FragOffset * 8

		if fragOffset == currentOffset {
			// Normal case: fragment starts where we expect
			payload = append(payload, frag.Payload...)
			currentOffset += frag.Length - uint16(frag.IHL)*4
		} else if fragOffset < currentOffset {
			// Overlapping fragment: take only the new bytes
			startAt := currentOffset - fragOffset
			fragPayloadLen := frag.Length - uint16(frag.IHL)*4
			if startAt >= fragPayloadLen {
				// Completely overlapped, skip
				continue
			}
			payload = append(payload, frag.Payload[startAt:]...)
			currentOffset += fragPayloadLen - startAt
		} else {
			// Gap in fragments - reassembly failed
			return nil, errors.New("defrag: hole in fragment sequence")
		}
	}

	// Create reassembled IPv4 layer
	out := &layers.IPv4{
		Version:    in.Version,
		IHL:        in.IHL,
		TOS:        in.TOS,
		Length:     uint16(in.IHL)*4 + uint16(len(payload)),
		Id:         in.Id,
		Flags:      0, // Clear fragment flags
		FragOffset: 0, // Clear fragment offset
		TTL:        in.TTL,
		Protocol:   in.Protocol,
		Checksum:   0, // Will be recalculated during serialization
		SrcIP:      in.SrcIP,
		DstIP:      in.DstIP,
		Options:    in.Options,
		Padding:    in.Padding,
	}
	out.Payload = payload

	return out, nil
}
