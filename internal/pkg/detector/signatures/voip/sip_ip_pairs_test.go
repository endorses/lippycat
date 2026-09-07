package voip

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestSIPIPPairIdleExpiryIsBounded(t *testing.T) {
	s := NewSIPSignature()
	for i := 0; i < sipIPPairSweepBatchSize*2+7; i++ {
		s.recordSIPIPPair(fmt.Sprint(i), "proxy")
	}
	future := time.Now().Add(s.sipIPPairTTL + time.Second)
	require.Equal(t, sipIPPairSweepBatchSize, s.sweepSIPIPPairs(future, sipIPPairSweepBatchSize))
	require.Equal(t, sipIPPairSweepBatchSize+7, s.SIPIPPairStats()["entries"])
	require.Equal(t, sipIPPairSweepBatchSize, s.sweepSIPIPPairs(future, sipIPPairSweepBatchSize))
	require.Equal(t, 7, s.sweepSIPIPPairs(future, sipIPPairSweepBatchSize))
	require.Equal(t, 0, s.SIPIPPairStats()["entries"])
	require.Equal(t, uint64(sipIPPairSweepBatchSize*2+7), s.SIPIPPairStats()["ttl_evictions"])
	require.Zero(t, s.sipIPPairOrder.Len())
}

func TestSIPIPPairLiveAndRefreshOrdering(t *testing.T) {
	s := NewSIPSignature()
	s.maxSIPIPPairs = 2
	s.recordSIPIPPair("a", "proxy")
	s.recordSIPIPPair("b", "proxy")
	require.True(t, s.isKnownSIPIPPair("proxy", "a"))
	require.Zero(t, s.SweepSIPIPPairs())
	// A fresh SIP observation moves a behind b; a lookup alone must not.
	s.recordSIPIPPair("proxy", "a")
	require.Equal(t, 2, s.SIPIPPairStats()["entries"])
	s.recordSIPIPPair("c", "proxy")
	require.False(t, s.isKnownSIPIPPair("b", "proxy"))
	require.True(t, s.isKnownSIPIPPair("a", "proxy"))
	s.recordSIPIPPair("d", "proxy")
	require.False(t, s.isKnownSIPIPPair("a", "proxy"))
	require.Equal(t, 2, s.SIPIPPairStats()["entries"])
	require.Equal(t, uint64(2), s.SIPIPPairStats()["cap_evictions"])
}

func TestSIPIPPairLazyExpiryAndRefresh(t *testing.T) {
	s := NewSIPSignature()
	s.recordSIPIPPair("a", "proxy")
	s.knownSIPIPPairs[normalizeSIPIPPair("a", "proxy")].Value.(*sipIPEntry).timestamp = time.Now().Add(-time.Hour)
	require.False(t, s.isKnownSIPIPPair("a", "proxy"))
	require.Equal(t, uint64(1), s.SIPIPPairStats()["ttl_evictions"])
	s.recordSIPIPPair("a", "proxy")
	s.recordSIPIPPair("b", "proxy")
	for _, e := range s.knownSIPIPPairs {
		e.Value.(*sipIPEntry).timestamp = time.Now().Add(-time.Hour)
	}
	s.recordSIPIPPair("a", "proxy")
	require.Equal(t, 1, s.SweepSIPIPPairs())
	require.True(t, s.isKnownSIPIPPair("a", "proxy"))
}

func TestSIPIPPairConfiguredCap(t *testing.T) {
	old := viper.Get("detector.max_sip_ip_pairs")
	t.Cleanup(func() { viper.Set("detector.max_sip_ip_pairs", old) })
	for _, cap := range []int{3, 0, -1} {
		viper.Set("detector.max_sip_ip_pairs", cap)
		s := NewSIPSignature()
		expected := cap
		if cap <= 0 {
			expected = DefaultMaxSIPIPPairs
		}
		require.Equal(t, expected, s.SIPIPPairStats()["max_entries"])
	}
}

func TestSIPIPPairConcurrentAccess(t *testing.T) {
	s := NewSIPSignature()
	s.maxSIPIPPairs = 32
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := fmt.Sprintf("%d:%d", g, i%64)
				s.recordSIPIPPair(ip, "proxy")
				s.isKnownSIPIPPair("proxy", ip)
				s.SweepSIPIPPairs()
				if s.SIPIPPairStats()["entries"].(int) > 32 {
					t.Error("entry cap exceeded")
				}
			}
		}(g)
	}
	wg.Wait()
	require.Equal(t, len(s.knownSIPIPPairs), s.sipIPPairOrder.Len())
}
