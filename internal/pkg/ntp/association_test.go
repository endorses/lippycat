package ntp

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAssociationMatchingAndAmbiguity(t *testing.T) {
	a, err := NewAssociator(DefaultConfig())
	require.NoError(t, err)
	src, dst := netip.MustParseAddrPort("192.0.2.1:49152"), netip.MustParseAddrPort("192.0.2.2:123")
	at := time.Unix(100, 0)
	req := Observation{Mode: 3, Transmit: Timestamp{Raw: 12345}}
	reply := Observation{Mode: 4, Origin: Timestamp{Raw: 12345}}
	first := a.Observe("scope", src, dst, at, &req)
	require.Equal(t, AssociationRequest, first.Status)
	require.NotEmpty(t, first.ID)
	require.Equal(t, AssociationMissing, a.Observe("other", dst, src, at, &reply).Status)
	require.Equal(t, AssociationMissing, a.Observe("scope", src, dst, at, &reply).Status)
	require.Equal(t, AssociationMissing, a.Observe("scope", dst, netip.MustParseAddrPort("192.0.2.1:49153"), at, &reply).Status)
	matched := a.Observe("scope", dst, src, at.Add(time.Second), &reply)
	require.Equal(t, AssociationUnique, matched.Status)
	require.Equal(t, first.ID, matched.ID)
	// Reply retransmissions remain observations and do not consume association.
	require.Equal(t, matched, a.Observe("scope", dst, src, at.Add(2*time.Second), &reply))
	require.Equal(t, AssociationAmbiguous, a.Observe("scope", src, dst, at.Add(3*time.Second), &req).Status)
	ambiguous := a.Observe("scope", dst, src, at.Add(4*time.Second), &reply)
	require.Equal(t, AssociationAmbiguous, ambiguous.Status)
	require.Empty(t, ambiguous.ID)
	for _, mode := range []byte{1, 2, 5} {
		require.Equal(t, AssociationNotApplicable, a.Observe("scope", src, dst, at, &Observation{Mode: mode}).Status)
	}
}

func TestAssociationLimitsExpiryReset(t *testing.T) {
	for _, cfg := range []Config{{}, {MaxEntries: -1, MaxBytes: 256, Timeout: time.Second}, {MaxEntries: 1, MaxBytes: -1, Timeout: time.Second}, {MaxEntries: 1, MaxBytes: 256, Timeout: -time.Second}} {
		_, err := NewAssociator(cfg)
		require.Error(t, err)
	}
	cfg := Config{MaxEntries: 1, MaxBytes: AssociationEntryBytes, Timeout: time.Second}
	a, err := NewAssociator(cfg)
	require.NoError(t, err)
	src, dst := netip.MustParseAddrPort("[2001:db8::1]:49152"), netip.MustParseAddrPort("[2001:db8::2]:123")
	at := time.Unix(100, 0)
	req := Observation{Mode: 3, Transmit: Timestamp{Raw: 1}}
	a.Observe("a", src, dst, at, &req)
	a.Observe("b", src, dst, at, &req)
	require.Equal(t, uint64(1), a.Stats().Evicted)
	require.Equal(t, int64(256), a.Stats().Bytes)
	a.Advance(at.Add(2 * time.Second))
	require.Equal(t, 0, a.Stats().Entries)
	require.Equal(t, AssociationExpired, a.Observe("a", src, dst, at, &req).Status)
	require.Equal(t, 0, a.Stats().Entries)
	require.Equal(t, AssociationRequest, a.Observe("a", src, dst, at.Add(2*time.Second), &req).Status)
	a.Reset()
	require.Equal(t, 0, a.Stats().Entries)
	require.Equal(t, AssociationRequest, a.Observe("a", src, dst, at, &req).Status)
	cfg.MaxBytes = 1
	b, err := NewAssociator(cfg)
	require.NoError(t, err)
	require.Equal(t, AssociationCapacitySuppressed, b.Observe("a", src, dst, at, &req).Status)
	require.Zero(t, b.Stats().Entries)
}

func TestAssociationPartialAndConcurrent(t *testing.T) {
	a, err := NewAssociator(DefaultConfig())
	require.NoError(t, err)
	src, dst := netip.MustParseAddrPort("127.0.0.1:1234"), netip.MustParseAddrPort("127.0.0.2:123")
	at := time.Unix(100, 0)
	require.Equal(t, AssociationMissing, a.Observe("a", src, dst, at, &Observation{Mode: 3}).Status)
	require.Equal(t, AssociationMissing, a.Observe("a", src, dst, at, &Observation{Mode: 3, Partial: true, Transmit: Timestamp{Raw: 1}}).Status)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a.Observe("a", src, dst, at, &Observation{Mode: 3, Transmit: Timestamp{Raw: uint64(i + 1)}})
			a.Stats()
			a.Advance(at)
		}(i)
	}
	wg.Wait()
	require.Equal(t, 10, a.Stats().Entries)
}

func TestLateRequestDoesNotReviveEvictedAssociation(t *testing.T) {
	a, err := NewAssociator(Config{MaxEntries: 1, MaxBytes: AssociationEntryBytes, Timeout: time.Minute})
	require.NoError(t, err)
	src, dst := netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("192.0.2.2:123")
	at := time.Unix(100, 0)
	first := Observation{Mode: 3, Transmit: Timestamp{Raw: 1}}
	second := Observation{Mode: 3, Transmit: Timestamp{Raw: 2}}
	require.Equal(t, AssociationRequest, a.Observe("scope", src, dst, at, &first).Status)
	require.Equal(t, AssociationRequest, a.Observe("scope", src, dst, at.Add(2*time.Second), &second).Status)
	require.Equal(t, AssociationExpired, a.Observe("scope", src, dst, at.Add(time.Second), &first).Status)
	require.Equal(t, AssociationMissing, a.Observe("scope", dst, src, at.Add(3*time.Second), &Observation{Mode: 4, Origin: Timestamp{Raw: 1}}).Status)
	require.Equal(t, 1, a.Stats().Entries)
}
