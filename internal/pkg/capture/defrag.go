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

// IPv4Defragmenter reassembles fragmented IPv4 packets.
// It maintains state for multiple concurrent flows identified by
// (source IP, destination IP, fragment ID).
type IPv4Defragmenter struct {
	mu      sync.Mutex
	ipFlows map[ipv4FlowKey]*fragmentList
}

// NewIPv4Defragmenter creates a new defragmenter with an initialized flow map.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	return &IPv4Defragmenter{
		ipFlows: make(map[ipv4FlowKey]*fragmentList),
	}
}

// ipv4FlowKey uniquely identifies a fragmented packet flow
type ipv4FlowKey struct {
	flow gopacket.Flow // src/dst IP pair
	id   uint16        // IP identification field
}

// fragmentList holds fragments for a single IP packet being reassembled
type fragmentList struct {
	List          list.List // Ordered list of fragments
	Highest       uint16    // Highest byte offset seen (offset + length)
	Current       uint16    // Total bytes received so far
	FinalReceived bool      // True when last fragment (MF=0) received
	LastSeen      time.Time // For cleanup of stale fragments
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

	// Perform security checks
	if err := d.securityChecks(in); err != nil {
		return nil, err
	}

	// Create flow key for this fragment
	key := ipv4FlowKey{
		flow: in.NetworkFlow(),
		id:   in.Id,
	}

	// Get or create fragment list for this flow
	d.mu.Lock()
	fl, exists := d.ipFlows[key]
	if !exists {
		fl = &fragmentList{}
		d.ipFlows[key] = fl
	}
	d.mu.Unlock()

	// Insert fragment and attempt reassembly
	out, err := fl.insert(in, t)

	// Check for fragment list overflow (DoS protection)
	if out == nil && fl.List.Len()+1 > IPv4MaximumFragmentListLen {
		d.flush(key)
		return nil, fmt.Errorf("defrag: fragment list exceeded maximum size (%d)", IPv4MaximumFragmentListLen)
	}

	// Clean up completed flow
	if out != nil {
		d.flush(key)
		return out, nil
	}

	return nil, err
}

// DiscardOlderThan removes all fragment lists that haven't been updated
// since time t. Returns the number of flows discarded.
// This should be called periodically to prevent memory leaks from
// incomplete fragment sequences.
func (d *IPv4Defragmenter) DiscardOlderThan(t time.Time) int {
	var count int
	d.mu.Lock()
	for key, fl := range d.ipFlows {
		if fl.LastSeen.Before(t) {
			delete(d.ipFlows, key)
			count++
		}
	}
	d.mu.Unlock()
	return count
}

// flush removes the fragment list for a specific flow
func (d *IPv4Defragmenter) flush(key ipv4FlowKey) {
	d.mu.Lock()
	delete(d.ipFlows, key)
	d.mu.Unlock()
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

	return nil
}

// insert adds a fragment to the list and returns the reassembled packet
// if all fragments have been received.
func (fl *fragmentList) insert(in *layers.IPv4, t time.Time) (*layers.IPv4, error) {
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

	fl.LastSeen = t

	// Calculate fragment payload length (IP length - IP header)
	fragLength := in.Length - uint16(in.IHL)*4

	// Update tracking counters
	if fl.Highest < fragOffset+fragLength {
		fl.Highest = fragOffset + fragLength
	}
	fl.Current += fragLength

	// Check if this is the final fragment
	if in.Flags&layers.IPv4MoreFragments == 0 {
		fl.FinalReceived = true
	}

	// Attempt reassembly if we have the final fragment and all bytes
	if fl.FinalReceived && fl.Highest == fl.Current {
		return fl.build(in)
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
