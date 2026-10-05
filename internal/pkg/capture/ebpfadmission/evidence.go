//go:build linux

package ebpfadmission

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

// Decision is diagnostic evidence at packet evaluation time. Fingerprint is a
// bounded header hash and may collide; it is not an exact identity or payload.
// TimeNS uses the kernel monotonic clock, not wall clock. Lost ring events and
// sampling must be included when interpreting evidence.
type Decision struct {
	TimeNS              uint64
	Generation          uint64
	Domain              mediaadmission.DomainID
	Reason              uint32
	Length              uint32
	Fingerprint         uint32
	Source, Destination mediaadmission.EndpointKey
	IdentityLength      uint32
	Identity            [256]byte
	SampleEvery         uint32
}

var ReasonNames = [16]string{"unselected-media", "selected-endpoint", "signaling", "independent-selector", "no-filters", "non-udp", "fragment-compatibility", "encapsulation-compatibility", "unknown-compatibility", "shadow", "degraded-open", "evidence-lost", "explicit-restriction", "explicit-protocol-restriction", "reserved", "reserved"}

func DecodeDecision(raw []byte) (Decision, error) {
	if len(raw) != 344 {
		return Decision{}, fmt.Errorf("invalid decision record size %d", len(raw))
	}
	var wire struct {
		TimeNS, Generation                  uint64
		Domain, Reason, Length, Fingerprint uint32
		Source, Destination                 endpoint
		IdentityLength                      uint32
		Identity                            [256]byte
		SampleEvery                         uint32
	}
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &wire); err != nil {
		return Decision{}, err
	}
	if wire.Reason >= uint32(len(ReasonNames)) || wire.TimeNS == 0 {
		return Decision{}, fmt.Errorf("invalid decision reason or monotonic timestamp")
	}
	if wire.IdentityLength != 0 && (wire.IdentityLength > 256 || wire.IdentityLength != wire.Length) {
		return Decision{}, fmt.Errorf("invalid complete-frame identity length")
	}
	return Decision{TimeNS: wire.TimeNS, Generation: wire.Generation, Domain: mediaadmission.DomainID(wire.Domain), Reason: wire.Reason, Length: wire.Length, Fingerprint: wire.Fingerprint, Source: unpack(wire.Source), Destination: unpack(wire.Destination), IdentityLength: wire.IdentityLength, Identity: wire.Identity, SampleEvery: wire.SampleEvery}, nil
}
