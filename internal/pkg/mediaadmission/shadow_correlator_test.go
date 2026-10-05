package mediaadmission

import (
	"encoding/binary"
	"github.com/stretchr/testify/require"
	"testing"
)

func sampledShadowFixture(t *testing.T) (*ShadowCorrelator, OwnerID, ShadowSample, []byte) {
	t.Helper()
	c, owner, sample, _ := shadowFixture()
	c.sampleEvery = 8
	frame := shadowFrameWithEligibility(t, 0, 8, true, 0)
	sample.SampleEvery = 8
	sample.Length, sample.IdentityLength = uint32(len(frame)), uint32(len(frame))
	copy(sample.Identity[:], frame)
	return c, owner, sample, frame
}

func shadowFrameWithEligibility(t *testing.T, domain DomainID, interval uint32, eligible bool, start uint32) []byte {
	t.Helper()
	frame := make([]byte, 64)
	for i := start; i < start+10000; i++ {
		binary.LittleEndian.PutUint32(frame[60:], i)
		if ShadowFrameEligible(domain, frame, interval) == eligible {
			return frame
		}
	}
	t.Fatal("synthetic eligibility fixture unavailable")
	return nil
}

func TestSampledShadowArrivalOrdersAndEligibleDuplicates(t *testing.T) {
	for _, order := range []string{"soa", "sao", "osa", "oas", "aso", "aos"} {
		for _, duplicate := range []byte{0, 's', 'o', 'a'} {
			label := map[byte]string{0: "unique", 's': "sample duplicate", 'o': "observation duplicate", 'a': "attribution duplicate"}[duplicate]
			t.Run(order+"/"+label, func(t *testing.T) {
				c, owner, sample, frame := sampledShadowFixture(t)
				record := func(hook byte) {
					switch hook {
					case 's':
						c.Sample(sample, 45)
					case 'o':
						c.Observed(0, frame, 46)
					case 'a':
						c.Attributed(owner, 0, frame, 47)
					}
				}
				for i := range order {
					record(order[i])
				}
				if duplicate != 0 {
					record(duplicate)
				}
				c.Advance(300)
				if duplicate == 0 {
					require.Equal(t, uint64(1), c.Snapshot().RejectedAfterPublication)
					require.Zero(t, c.Snapshot().Incomplete)
				} else {
					require.Zero(t, c.Snapshot().RejectedAfterPublication)
					require.NotZero(t, c.Snapshot().Ambiguous)
				}
			})
		}
	}
}

func TestUnsampledBackgroundDoesNotConsumeRetentionOrCreateLoss(t *testing.T) {
	c, owner, sample, frame := sampledShadowFixture(t)
	c.capacity = 1
	c.Observed(0, frame, 46) // retain observation before asynchronous kernel read
	background := make([]byte, 64)
	for i := uint32(0); i < 10000; i++ {
		binary.LittleEndian.PutUint32(background[60:], i)
		if c.FrameEligible(0, background) {
			continue
		}
		// Eligibility must precede the lock as well as capacity accounting.
		c.mu.Lock()
		c.Observed(0, background, 48)
		c.Attributed(owner, 0, background, 49)
		c.mu.Unlock()
	}
	require.Equal(t, 1, c.Snapshot().Pending)
	require.Zero(t, c.Snapshot().TrackingRejected)
	require.Zero(t, c.evidenceEpoch.Load())
	c.Sample(sample, 50)
	c.Attributed(owner, 0, frame, 51)
	c.Advance(300)
	require.Equal(t, uint64(1), c.Snapshot().RejectedAfterPublication)
	require.Zero(t, c.Snapshot().Incomplete)
}

func TestEligibleShadowCapacityLossRemainsIncomplete(t *testing.T) {
	c, owner, sample, frame := sampledShadowFixture(t)
	c.capacity = 1
	shadowEvidence(c, owner, sample, frame)
	other := shadowFrameWithEligibility(t, 0, 8, true, binary.LittleEndian.Uint32(frame[60:])+1)
	c.Observed(0, other, 48)
	require.Equal(t, uint64(1), c.Snapshot().TrackingRejected)
	require.NotZero(t, c.evidenceEpoch.Load())
	c.Advance(300)
	require.Equal(t, uint64(1), c.Snapshot().Incomplete)
	require.Zero(t, c.Snapshot().RejectedAfterPublication)
}

func TestShadowSamplingMismatchInvalidatesPendingEvidence(t *testing.T) {
	for _, scenario := range []string{"missing interval", "different interval", "unexpected identity"} {
		t.Run(scenario, func(t *testing.T) {
			c, owner, sample, frame := sampledShadowFixture(t)
			shadowEvidence(c, owner, sample, frame)
			mismatch := sample
			switch scenario {
			case "missing interval":
				mismatch.SampleEvery = 0
			case "different interval":
				mismatch.SampleEvery = 1
			case "unexpected identity":
				copy(mismatch.Identity[:], shadowFrameWithEligibility(t, 0, 8, false, 0))
			}
			c.Sample(mismatch, 50)
			require.Equal(t, 1, c.Snapshot().Pending, "mismatch never creates retained evidence")
			c.Advance(300)
			require.Equal(t, uint64(2), c.Snapshot().Incomplete)
			require.Zero(t, c.Snapshot().RejectedAfterPublication)
		})
	}
}

func shadowFixture() (*ShadowCorrelator, OwnerID, ShadowSample, []byte) {
	c := NewShadowCorrelator(4, 2, 100)
	owner := OwnerID{Session: 1, Generation: 1, CallID: "synthetic"}
	c.Selection(owner, 0, 20)
	c.Expectation(owner, 0, true, true, 1, 30, 3)
	frame := []byte{1, 2, 3, 4, 5}
	sample := ShadowSample{SampleEvery: 1, Domain: 0, Generation: 3, EventMonotonicNS: 40, Length: 5, IdentityLength: 5, Fingerprint: 7}
	copy(sample.Identity[:], frame)
	return c, owner, sample, frame
}
func shadowEvidence(c *ShadowCorrelator, owner OwnerID, sample ShadowSample, frame []byte) {
	c.Sample(sample, 45)
	c.Observed(0, frame, 46)
	c.Attributed(owner, 0, frame, 47)
}

func TestLateEligibleDuplicateInvalidatesPendingClassification(t *testing.T) {
	for _, sampled := range []bool{false, true} {
		label := map[bool]string{false: "all", true: "sampled"}[sampled]
		for _, reason := range []uint32{0, 1} {
			outcome := map[uint32]string{0: "rejected", 1: "admitted"}[reason]
			t.Run(label+"/"+outcome, func(t *testing.T) {
				c, owner, sample, frame := shadowFixture()
				if sampled {
					c, owner, sample, frame = sampledShadowFixture(t)
				}
				sample.Reason = reason
				shadowEvidence(c, owner, sample, frame)
				// A second kernel copy can be delivered late without a second
				// captured copy or a ring reservation loss. Its exact bytes still
				// disprove uniqueness of the pending tuple.
				sample.EventMonotonicNS = 41
				c.Sample(sample, 200)
				c.Advance(300)
				stats := c.Snapshot()
				require.Equal(t, uint64(1), stats.Late)
				require.Equal(t, uint64(2), stats.Incomplete, "both eligible kernel copies remain unclassified")
				require.Zero(t, stats.Admitted)
				require.Zero(t, stats.RejectedAfterPublication)
				require.Zero(t, stats.Pending)
			})
		}
	}
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
	sample := ShadowSample{SampleEvery: 1, Domain: 0, Generation: 3, EventMonotonicNS: 40, Length: 1, IdentityLength: 1, Identity: [256]byte{1}}
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
	sample := ShadowSample{SampleEvery: 1, Domain: 0, Generation: 0, EventMonotonicNS: 10, Length: 3, IdentityLength: 3, Identity: [256]byte{1, 2, 3}}
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
