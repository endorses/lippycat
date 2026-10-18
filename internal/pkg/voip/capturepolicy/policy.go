// Package capturepolicy defines source policies without depending on VoIP runtimes.
package capturepolicy

import (
	"bytes"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket"
)

// SignallingPolicy controls SIP export independently of media selection.
type SignallingPolicy string

const (
	SignallingMatched SignallingPolicy = "matched"
	SignallingAll     SignallingPolicy = "all"
	SignallingNone    SignallingPolicy = "none"
)

// MediaPolicy controls the authority that selects media packets.
type MediaPolicy string

const (
	MediaLocal     MediaPolicy = "local"
	MediaProcessor MediaPolicy = "processor"
)

type CapturePolicies struct {
	Signalling SignallingPolicy
	Media      MediaPolicy
}

func (p CapturePolicies) Normalize() (CapturePolicies, error) {
	if p.Signalling == "" {
		p.Signalling = SignallingMatched
	}
	if p.Media == "" {
		p.Media = MediaLocal
	}
	if p.Signalling != SignallingMatched && p.Signalling != SignallingAll && p.Signalling != SignallingNone {
		return p, fmt.Errorf("invalid signalling policy %q: expected matched, all or none", p.Signalling)
	}
	if p.Media != MediaLocal && p.Media != MediaProcessor {
		return p, fmt.Errorf("invalid media policy %q: expected local or processor", p.Media)
	}
	return p, nil
}

// RemoteCallAssociation is current processor-authorized call attribution.
// Filter IDs represent inherited evidence; they must never become direct matches.
type RemoteCallAssociation struct {
	Lifetime              callregistry.Lifetime
	SelectionRevision     uint64
	CapturePolicyRevision uint64
	ProcessorID           string
	ControlGeneration     uint64
	CallID                string
	InheritedFilterIDs    []string
	CaptureSelectionProof []byte
}

// Clone owns the variable selection evidence retained by queued callbacks.
func (a RemoteCallAssociation) Clone() RemoteCallAssociation {
	a.InheritedFilterIDs = append([]string(nil), a.InheritedFilterIDs...)
	a.CaptureSelectionProof = append([]byte(nil), a.CaptureSelectionProof...)
	return a
}

// RemoteMediaResolver must fail closed on expired, withdrawn, stale, ambiguous or
// wrong-domain rules. ResolveMedia requires exact RTP/RTCP endpoint ownership.
// ResolveSignalling additionally validates dialog tags and transaction evidence;
// a matching Call-ID alone is insufficient. Each call must consult current state.
type RemoteMediaResolver interface {
	ResolveMedia(gopacket.Packet, string) (RemoteCallAssociation, bool)
	ResolveSignalling(sharedsip.Event, gopacket.Packet, string) (RemoteCallAssociation, bool)
}

// RemoteMediaProofValidator rechecks original capture-time proof separately
// from a resolver's current live selection. Buffered packets never get retagged.
type RemoteMediaProofValidator interface {
	ValidateMediaProof(gopacket.Packet, string, []byte, time.Time) bool
}

// SameSelection compares opaque authority without treating it as a local registry
// capability. Signed media evidence must remain byte-identical while queued.
func (a RemoteCallAssociation) SameSelection(b RemoteCallAssociation) bool {
	return a.CallID == b.CallID && a.Lifetime == b.Lifetime && a.SelectionRevision == b.SelectionRevision && a.CapturePolicyRevision == b.CapturePolicyRevision && a.ProcessorID == b.ProcessorID && a.ControlGeneration == b.ControlGeneration && bytes.Equal(a.CaptureSelectionProof, b.CaptureSelectionProof)
}

// FilterSelectionProof freezes semantic filter definitions at direct matching.
// Lease renewals preserve the proof; same-ID pattern replacement invalidates it.
type FilterSelectionProof map[string][32]byte

type SelectionProofMatcher interface {
	MatchPacketWithSelectionProof(gopacket.Packet) (bool, []string, FilterSelectionProof)
	CurrentSelection(FilterSelectionProof) (bool, []string)
}

// MergeProofs copies captured evidence without reinterpreting old filter IDs.
func MergeProofs(prior, current FilterSelectionProof) FilterSelectionProof {
	merged := make(FilterSelectionProof, len(prior)+len(current))
	for id, fingerprint := range prior {
		merged[id] = fingerprint
	}
	for id, fingerprint := range current {
		merged[id] = fingerprint
	}
	return merged
}

// MergeCurrentProofs retires obsolete definitions before retaining new evidence,
// so a long call cannot accumulate IDs removed by successive filter updates.
func MergeCurrentProofs(matcher SelectionProofMatcher, prior, current FilterSelectionProof) FilterSelectionProof {
	merged := MergeProofs(nil, current)
	for id, fingerprint := range prior {
		if valid, _ := matcher.CurrentSelection(FilterSelectionProof{id: fingerprint}); valid {
			if _, newer := merged[id]; !newer {
				merged[id] = fingerprint
			}
		}
	}
	return merged
}
