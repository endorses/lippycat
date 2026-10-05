package mediaadmission

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func shadowFixture() (*ShadowCorrelator, OwnerID, ShadowSample, []byte) {
	c := NewShadowCorrelator(4, 2, 100)
	owner := OwnerID{Session: 1, Generation: 1, CallID: "synthetic"}
	c.Selection(owner, 0, 20)
	c.Expectation(owner, 0, true, true, 1, 30, 3)
	frame := []byte{1, 2, 3, 4, 5}
	sample := ShadowSample{Domain: 0, Generation: 3, EventMonotonicNS: 40, Length: 5, IdentityLength: 5, Fingerprint: 7}
	copy(sample.Identity[:], frame)
	return c, owner, sample, frame
}
func shadowEvidence(c *ShadowCorrelator, owner OwnerID, sample ShadowSample, frame []byte) {
	c.Sample(sample, 45)
	c.Observed(0, frame, 46)
	c.Attributed(owner, 0, frame, 47)
}
func TestShadowCorrelatorSettlesVerifiedHistoricalPacket(t *testing.T) {
	for _, reason := range []uint32{0, 1} {
		c, owner, sample, frame := shadowFixture()
		sample.Reason = reason
		shadowEvidence(c, owner, sample, frame)
		c.Advance(200)
		require.Zero(t, c.Snapshot().RejectedAfterPublication, "do not settle before the duplicate window")
		c.Finalized(owner, 100)
		c.Advance(300)
		stats := c.Snapshot()
		if reason == 0 {
			require.Equal(t, uint64(1), stats.RejectedAfterPublication)
		} else {
			require.Equal(t, uint64(1), stats.Admitted)
		}
		require.Zero(t, stats.Incomplete)
		require.Zero(t, stats.Pending)
		c.Advance(500)
		require.Zero(t, c.Snapshot().Owners, "retired lifetime history must expire")
	}
}
func TestShadowCorrelatorKeepsUncertaintyExplicit(t *testing.T) {
	for _, scenario := range []string{"duplicate capture", "duplicate sample", "duplicate attribution", "missing observation", "missing attribution", "fingerprint collision", "new generation", "reinvite", "unknown", "inactive", "retired before packet", "late sample", "large frame", "truncated identity"} {
		t.Run(scenario, func(t *testing.T) {
			c, owner, sample, frame := shadowFixture()
			switch scenario {
			case "late sample":
				c.Sample(sample, 200)
			case "large frame":
				sample.IdentityLength = 0
				sample.Length = 1000
				c.Sample(sample, 45)
			case "truncated identity":
				sample.Length = 6
				c.Sample(sample, 45)
			default:
				c.Sample(sample, 45)
				if scenario != "missing observation" {
					c.Observed(0, frame, 46)
				}
				if scenario != "missing attribution" {
					attributedFrame := frame
					if scenario == "fingerprint collision" {
						attributedFrame = []byte{1, 2, 3, 4, 6}
					}
					c.Attributed(owner, 0, attributedFrame, 47)
				}
				switch scenario {
				case "duplicate capture":
					c.Observed(0, frame, 48)
				case "duplicate sample":
					c.Sample(sample, 48)
				case "duplicate attribution":
					c.Attributed(owner, 0, frame, 48)
				case "new generation":
					c.mu.Lock()
					for _, e := range c.entries {
						e.sample.Generation = 4
					}
					c.mu.Unlock()
				case "reinvite":
					c.Expectation(owner, 0, true, true, 2, 50, 4)
				case "unknown":
					c.Expectation(owner, 0, false, true, 1, 0, 0)
				case "inactive":
					c.Expectation(owner, 0, true, false, 2, 0, 0)
				case "retired before packet":
					c.Finalized(owner, 35)
				}
			}
			c.Advance(400)
			stats := c.Snapshot()
			require.Zero(t, stats.Admitted)
			require.Zero(t, stats.RejectedAfterPublication)
			require.NotZero(t, stats.Incomplete)
			require.Zero(t, stats.Pending)
		})
	}
}
func TestShadowCorrelatorPublicationAndPreselectionUncertainty(t *testing.T) {
	c, owner, sample, frame := shadowFixture()
	sample.EventMonotonicNS, sample.Generation = 25, 2
	shadowEvidence(c, owner, sample, frame)
	c.Advance(300)
	require.Equal(t, uint64(1), c.Snapshot().PublicationWindow)
	// Attribution learned after selection cannot establish ownership before the
	// known lifetime window, even with a byte-for-byte identity match.
	c, owner, sample, frame = shadowFixture()
	sample.EventMonotonicNS = 10
	shadowEvidence(c, owner, sample, frame)
	c.Advance(300)
	require.Equal(t, uint64(1), c.Snapshot().Incomplete)
}
func TestShadowCorrelatorCapacityAndDomainIsolation(t *testing.T) {
	c := NewShadowCorrelator(1, 1, 100)
	a := OwnerID{Session: 1, Generation: 1}
	b := OwnerID{Session: 1, Generation: 2}
	c.Selection(a, 0, 20)
	c.Selection(b, 1, 20)
	c.Expectation(a, 0, true, true, 1, 30, 3)
	frame := []byte{1}
	sample := ShadowSample{Domain: 0, Generation: 3, EventMonotonicNS: 40, Length: 1, IdentityLength: 1, Identity: [256]byte{1}}
	c.Sample(sample, 45)
	c.Observed(1, frame, 46)
	c.Attributed(a, 1, frame, 47)
	c.Advance(300)
	require.Equal(t, uint64(1), c.Snapshot().Incomplete)
	require.NotZero(t, c.Snapshot().TrackingRejected)
	require.LessOrEqual(t, c.Snapshot().Owners, 1)
}

func TestShadowCorrelatorPreselectionUsesVerifiedLifetimeStart(t *testing.T) {
	c := NewShadowCorrelator(4, 2, 100)
	owner := OwnerID{Session: 1, Generation: 1, CallID: "synthetic"}
	frame := []byte{1, 2, 3}
	sample := ShadowSample{Domain: 0, Generation: 0, EventMonotonicNS: 10, Length: 3, IdentityLength: 3, Identity: [256]byte{1, 2, 3}}
	c.Sample(sample, 15)
	c.Observed(0, frame, 16)
	c.Selection(owner, 0, 20)
	c.RecordLifetimeStart(owner, 0, 5)
	c.Expectation(owner, 0, true, true, 1, 30, 1)
	c.Attributed(owner, 0, frame, 35)
	c.Advance(300)
	require.Equal(t, uint64(1), c.Snapshot().Preselection)
	require.Zero(t, c.Snapshot().Incomplete)
}

func TestShadowPacketPressureIsNonblockingAndInvalidatesUniqueness(t *testing.T) {
	c, owner, sample, frame := shadowFixture()
	shadowEvidence(c, owner, sample, frame)
	// A duplicate lost behind maintenance must not leave the remaining complete
	// tuple looking unique. Holding the lock and invoking directly proves neither
	// packet hook waits for it.
	c.mu.Lock()
	c.Observed(0, frame, 48)
	c.Attributed(owner, 0, frame, 49)
	c.mu.Unlock()
	c.Advance(300)
	require.Equal(t, uint64(1), c.Snapshot().Incomplete)
	require.Equal(t, uint64(2), c.Snapshot().TrackingRejected)
	// Evidence arriving within the overlapping uncertainty window stays unknown.
	sample.EventMonotonicNS = 100
	c.Sample(sample, 105)
	c.Observed(0, frame, 106)
	c.Attributed(owner, 0, frame, 107)
	c.Advance(400)
	require.Equal(t, uint64(2), c.Snapshot().Incomplete)
	// Fresh complete evidence outside that bounded window may classify again.
	sample.EventMonotonicNS = 500
	c.Sample(sample, 505)
	c.Observed(0, frame, 506)
	c.Attributed(owner, 0, frame, 507)
	c.Advance(800)
	require.Equal(t, uint64(1), c.Snapshot().RejectedAfterPublication)
}
