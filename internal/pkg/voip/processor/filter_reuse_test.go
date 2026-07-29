package processor

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingFilter records how often each match method is called so tests can
// assert that a packet is evaluated exactly once.
type countingFilter struct {
	matched      bool
	ids          []string
	matchCalls   int
	withIDsCalls int
}

func (f *countingFilter) MatchPacket(gopacket.Packet) bool {
	f.matchCalls++
	return f.matched
}

func (f *countingFilter) MatchPacketWithIDs(gopacket.Packet) (bool, []string) {
	f.withIDsCalls++
	return f.matched, f.ids
}

func sipInvitePacket(t *testing.T, callID string) gopacket.Packet {
	t.Helper()
	return createUDPPacket(t, []byte("INVITE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 192.168.1.1:5060\r\n"+
		"From: Alice <sip:alice@example.com>;tag=1234\r\n"+
		"To: Bob <sip:bob@example.com>\r\n"+
		"Call-ID: "+callID+"\r\n"+
		"CSeq: 1 INVITE\r\n"+
		"Content-Length: 0\r\n\r\n"), 5060, 5060)
}

func newFilteredProcessor(f ApplicationFilter, needIDs bool) *Processor {
	cfg := DefaultConfig()
	cfg.ApplicationFilter = f
	cfg.NeedFilterIDs = needIDs
	return New(cfg)
}

// A matching packet must be evaluated once and carry the verdict plus IDs, so
// the caller can forward it without matching the same packet again.
func TestFilterVerdict_MatchEvaluatedOnceWithIDs(t *testing.T) {
	f := &countingFilter{matched: true, ids: []string{"li-1"}}
	p := newFilteredProcessor(f, true)
	defer p.Close()

	result := p.Process(sipInvitePacket(t, "match@example.com"))

	require.NotNil(t, result)
	assert.True(t, result.IsVoIP)
	assert.True(t, result.FilterEvaluated)
	assert.True(t, result.FilterMatched)
	assert.Equal(t, []string{"li-1"}, result.FilterIDs)

	assert.Equal(t, 1, f.withIDsCalls, "packet must be matched exactly once")
	assert.Equal(t, 0, f.matchCalls, "boolean match must not also run when IDs are needed")
}

// A non-matching packet is not tracked, but must still report the verdict so the
// caller can drop it without re-running the filter.
func TestFilterVerdict_NonMatchReportsVerdict(t *testing.T) {
	f := &countingFilter{matched: false}
	p := newFilteredProcessor(f, true)
	defer p.Close()

	result := p.Process(sipInvitePacket(t, "nomatch@example.com"))

	require.NotNil(t, result, "verdict must be reported instead of a bare nil")
	assert.False(t, result.IsVoIP)
	assert.True(t, result.FilterEvaluated)
	assert.False(t, result.FilterMatched)
	assert.Equal(t, 1, f.withIDsCalls)

	assert.Empty(t, p.ActiveCalls(), "non-matching call must not be tracked")
}

// Without NeedFilterIDs the cheaper boolean match is used (it can take the GPU
// path), and the verdict is still reported.
func TestFilterVerdict_BooleanMatchWhenIDsNotNeeded(t *testing.T) {
	f := &countingFilter{matched: true}
	p := newFilteredProcessor(f, false)
	defer p.Close()

	result := p.Process(sipInvitePacket(t, "boolean@example.com"))

	require.NotNil(t, result)
	assert.True(t, result.FilterEvaluated)
	assert.True(t, result.FilterMatched)
	assert.Equal(t, 1, f.matchCalls)
	assert.Equal(t, 0, f.withIDsCalls)
}

// With no filter configured nothing is evaluated, so callers must fall back to
// their own matching rather than trusting an empty verdict.
func TestFilterVerdict_NoFilterMeansNotEvaluated(t *testing.T) {
	p := New(DefaultConfig())
	defer p.Close()

	result := p.Process(sipInvitePacket(t, "nofilter@example.com"))

	require.NotNil(t, result)
	assert.True(t, result.IsVoIP)
	assert.False(t, result.FilterEvaluated)
}

// In-dialog messages for an already-tracked call must still be processed even
// when they no longer carry the matched identity.
func TestFilterVerdict_TrackedCallSurvivesLaterNonMatch(t *testing.T) {
	f := &countingFilter{matched: true, ids: []string{"li-1"}}
	p := newFilteredProcessor(f, true)
	defer p.Close()

	require.NotNil(t, p.Process(sipInvitePacket(t, "dialog@example.com")))
	require.Len(t, p.ActiveCalls(), 1)

	// A later message for the same call that no longer matches the filter.
	f.matched = false
	f.ids = nil
	result := p.Process(sipInvitePacket(t, "dialog@example.com"))

	require.NotNil(t, result)
	assert.True(t, result.IsVoIP, "in-dialog message for a tracked call must still be processed")
	assert.Len(t, p.ActiveCalls(), 1)
}
