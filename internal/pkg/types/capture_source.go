package types

import (
	"errors"
	"unicode/utf8"
)

// MaxCaptureSourceStringBytes bounds each source identifier in capture products.
const MaxCaptureSourceStringBytes = 4096

// ErrInvalidCaptureSource identifies missing, malformed or unbounded source facts.
var ErrInvalidCaptureSource = errors.New("invalid capture source")

// CaptureSource is an immutable origin value, independent of delivery identity
// and capture time. Its zero value means unavailable, not a configured processor.
// A known observation domain of zero is distinct from an unknown domain.
type CaptureSource struct {
	nodeID      string
	intf        string
	domain      uint32
	domainKnown bool
}

// NewCaptureSource validates source facts without inventing absent identities.
func NewCaptureSource(nodeID, intf string, domain uint32, known bool) (CaptureSource, error) {
	if nodeID == "" || intf == "" || len(nodeID) > MaxCaptureSourceStringBytes || len(intf) > MaxCaptureSourceStringBytes || !utf8.ValidString(nodeID) || !utf8.ValidString(intf) || (!known && domain != 0) {
		return CaptureSource{}, ErrInvalidCaptureSource
	}
	return CaptureSource{nodeID: nodeID, intf: intf, domain: domain, domainKnown: known}, nil
}

func (s CaptureSource) NodeID() string                    { return s.nodeID }
func (s CaptureSource) Interface() string                 { return s.intf }
func (s CaptureSource) ObservationDomain() (uint32, bool) { return s.domain, s.domainKnown }
