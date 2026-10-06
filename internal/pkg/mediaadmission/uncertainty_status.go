package mediaadmission

// UncertaintyReason indexes a fixed aggregate reason set. Counts overlap: one
// unknown call may have several reasons, so summing them does not count calls.
type UncertaintyReason uint8

const (
	ReasonConflictingHeaders UncertaintyReason = iota
	ReasonFaultyPRACK
	ReasonPartialSDP
	ReasonDelayedOffer
	ReasonForkAmbiguity
	ReasonEvidenceLoss
	UncertaintyReasonCount
)

// UncertaintyStats contains no call identities, endpoint data, or dynamic labels.
// Duplicate counts are cumulative occurrences, independent of active call counts.
type UncertaintyStats struct {
	UnknownCalls          uint64
	Reasons               [UncertaintyReasonCount]uint64
	IdenticalDuplicates   uint64
	ConflictingDuplicates uint64
}

// UpdateUncertainty publishes diagnostics without changing kernel policy. Unknown
// domains and disabled/closed controllers cannot create new scope state.
func (c *Controller) UpdateUncertainty(domain DomainID, stats UncertaintyStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if scope := c.scopes[domain]; scope != nil {
		scope.status.Uncertainty = stats
		c.publishStatusLocked()
	}
}
