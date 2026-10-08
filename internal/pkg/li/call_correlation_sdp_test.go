//go:build li

package li

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func sdpHistoryTestConfig() CallCorrelationConfig {
	return CallCorrelationConfig{SDPOriginReuseWindow: 30 * time.Second, SDPOriginObservationTTL: 10 * time.Minute, SDPOriginSuspend: time.Minute, SDPOriginMaxTracked: 10}
}
func sdpHistoryTestOrigin() sdpOrigin {
	return sdpOrigin{"-", "9999999999999999999999999", "IN", "IP4", "192.0.2.1"}
}
func TestCorrelationSDPOriginParsing(t *testing.T) {
	first, ok := parseCorrelationSDPOrigin("v=0\r\no=- 9999999999999999999999999 9999999999999999999999998 IN IP4 192.0.2.1\r\nm=audio 9 RTP/AVP 0\r\n")
	require.True(t, ok)
	require.Equal(t, sdpHistoryTestOrigin(), first.Identity)
	second, ok := parseCorrelationSDPOrigin("o=- 9999999999999999999999999 2 IN IP4 192.0.2.1\n")
	require.True(t, ok)
	require.Equal(t, first.Identity, second.Identity)
	require.NotEqual(t, first.Version, second.Version)
	long := strings.Repeat("x", 100)
	parsed, ok := parseCorrelationSDPOrigin("o=" + long + " 0 0 IN IP6 2001:db8::1\n")
	require.True(t, ok)
	require.Equal(t, long, parsed.Identity.Username)
	for _, body := range []string{"c=IN IP4 192.0.2.1\n", "o=- x 1 IN IP4 192.0.2.1", "o=- 1 2 IN IP4", "o=- 1 2 IN IP4 192.0.2.1\no=- 1 2 IN IP4 192.0.2.1", "m=audio 9 RTP/AVP 0\no=- 1 2 IN IP4 192.0.2.1", "o=" + strings.Repeat("a", correlationSDPMaxField+1) + " 1 2 IN IP4 192.0.2.1", strings.Repeat("x", correlationSDPMaxBody+1)} {
		_, ok := parseCorrelationSDPOrigin(body)
		require.False(t, ok, body[:min(len(body), 80)])
	}
}
func TestSDPOriginHistoryReuseAndRoleIsolation(t *testing.T) {
	h := newSDPOriginHistory(sdpHistoryTestConfig())
	now := time.Unix(1000, 0)
	origin := sdpHistoryTestOrigin()
	require.True(t, h.Observe(origin, sdpOriginOffer, "a", now.Add(40*time.Second), now, nil))
	require.True(t, h.Observe(origin, sdpOriginOffer, "a", now.Add(80*time.Second), now.Add(time.Second), nil))
	require.False(t, h.Observe(origin, sdpOriginOffer, "b", now, now.Add(2*time.Second), nil))
	entry := h.entries[sdpOriginHistoryKey{origin, sdpOriginOffer}]
	require.Equal(t, now, entry.firstSeen)
	require.Equal(t, now.Add(40*time.Second), entry.latestStart)
	require.True(t, h.Observe(origin, sdpOriginAnswer, "c", now, now.Add(3*time.Second), nil))
	require.False(t, h.Observe(origin, sdpOriginUnknown, "d", now, now, nil))
	require.Equal(t, 2, h.Len())
	require.False(t, h.Usable(origin, sdpOriginOffer, now.Add(3*time.Second)))
	require.True(t, h.Usable(origin, sdpOriginAnswer, now.Add(3*time.Second)))
}
func TestSDPOriginHistoryDistinctRefreshAndExpiry(t *testing.T) {
	h := newSDPOriginHistory(sdpHistoryTestConfig())
	now := time.Unix(1000, 0)
	origin := sdpHistoryTestOrigin()
	require.True(t, h.Observe(origin, sdpOriginOffer, "a", now, now, nil))
	require.True(t, h.Observe(origin, sdpOriginOffer, "a", now, now.Add(9*time.Minute), nil))
	h.Expire(now.Add(10 * time.Minute))
	require.Zero(t, h.Len())
	require.True(t, h.Observe(origin, sdpOriginOffer, "b", now.Add(time.Hour), now.Add(10*time.Minute), nil))
	require.True(t, h.Observe(origin, sdpOriginOffer, "c", now.Add(time.Hour+time.Second), now.Add(19*time.Minute), nil))
	h.Expire(now.Add(20 * time.Minute))
	require.Equal(t, 1, h.Len())
	h.Expire(now.Add(29 * time.Minute))
	require.Zero(t, h.Len())
}
func TestSDPOriginSuspensionFixedDeadlineAndRenewal(t *testing.T) {
	h := newSDPOriginHistory(sdpHistoryTestConfig())
	now := time.Unix(1000, 0)
	origin := sdpHistoryTestOrigin()
	require.True(t, h.Observe(origin, sdpOriginOffer, "a", now, now, map[string]string{"session-id": "one"}))
	require.False(t, h.Observe(origin, sdpOriginOffer, "b", now.Add(time.Second), now.Add(time.Second), map[string]string{"session-id": "two"}))
	entry := h.entries[sdpOriginHistoryKey{origin, sdpOriginOffer}]
	deadline := entry.suspendedUntil
	require.False(t, h.Observe(origin, sdpOriginOffer, "c", now.Add(2*time.Second), now.Add(30*time.Second), nil))
	require.Equal(t, deadline, entry.suspendedUntil)
	require.True(t, entry.renew)
	h.Expire(deadline)
	require.Equal(t, deadline.Add(time.Minute), entry.suspendedUntil)
	require.False(t, entry.renew)
	require.False(t, h.Observe(origin, sdpOriginOffer, "c", now.Add(2*time.Second), deadline.Add(time.Second), nil))
	h.Expire(deadline.Add(time.Minute))
	require.Zero(t, h.Len())
	require.True(t, h.Observe(origin, sdpOriginOffer, "d", now, deadline.Add(time.Minute), nil))
}
func TestSDPOriginSuspensionBoundaryHasNoGap(t *testing.T) {
	h := newSDPOriginHistory(sdpHistoryTestConfig())
	now := time.Unix(1000, 0)
	origin := sdpHistoryTestOrigin()
	h.Observe(origin, sdpOriginOffer, "a", now, now, nil)
	require.False(t, h.Observe(origin, sdpOriginOffer, "b", now.Add(40*time.Second), now.Add(time.Second), nil))
	entry := h.entries[sdpOriginHistoryKey{origin, sdpOriginOffer}]
	deadline := entry.suspendedUntil
	require.False(t, h.Observe(origin, sdpOriginOffer, "c", now.Add(41*time.Second), deadline.Add(-time.Nanosecond), nil))
	require.False(t, h.Observe(origin, sdpOriginOffer, "d", now.Add(42*time.Second), deadline, nil))
	require.True(t, entry.renew)
	require.Equal(t, deadline.Add(time.Minute), entry.suspendedUntil)
	h.Expire(deadline.Add(3 * time.Minute))
	require.Zero(t, h.Len())
}
func TestSDPOriginHistoryCapacityDoesNotEvict(t *testing.T) {
	config := sdpHistoryTestConfig()
	config.SDPOriginMaxTracked = 1
	h := newSDPOriginHistory(config)
	now := time.Unix(1000, 0)
	origin := sdpHistoryTestOrigin()
	other := origin
	other.SessionID = "2"
	require.True(t, h.Observe(origin, sdpOriginOffer, "a", now, now, nil))
	require.False(t, h.Observe(other, sdpOriginOffer, "b", now, now, nil))
	require.True(t, h.Disabled())
	require.Equal(t, 1, h.Len())
	require.False(t, h.Usable(origin, sdpOriginOffer, now))
	h.Expire(now.Add(10 * time.Minute))
	require.False(t, h.Disabled())
	require.Zero(t, h.Len())
	require.True(t, h.Observe(other, sdpOriginOffer, "c", now, now.Add(10*time.Minute), nil))
}

func TestSDPOriginHistoryTransactionBound(t *testing.T) {
	h := newSDPOriginHistory(sdpHistoryTestConfig())
	now := time.Unix(1000, 0)
	origin := sdpHistoryTestOrigin()
	for i := 0; i < correlationSDPMaxTransactions; i++ {
		require.True(t, h.Observe(origin, sdpOriginOffer, strings.Repeat("x", i+1), now, now, nil))
	}
	require.False(t, h.Observe(origin, sdpOriginOffer, "overflow", now, now, nil))
	require.True(t, h.Disabled())
	require.Len(t, h.entries[sdpOriginHistoryKey{origin, sdpOriginOffer}].transactions, correlationSDPMaxTransactions)
}
