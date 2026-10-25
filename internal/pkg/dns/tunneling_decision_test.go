package dns

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func clockedTunnelingConfig() TunnelingConfig {
	config := DefaultTunnelingConfig()
	config.DisableJanitor = true
	return config
}

func tunnelingObservation(domain string) *types.DNSMetadata {
	return &types.DNSMetadata{QueryName: "abcdefghijklmnopqrstuvwxyz0123456789." + domain, QueryType: "TXT"}
}

func TestAnalyzeAtUsesObservationClockWithoutCallbacks(t *testing.T) {
	detector := NewTunnelingDetector(clockedTunnelingConfig())
	t.Cleanup(detector.Stop)
	var callbacks atomic.Uint64
	detector.SetAlertConfig(AlertConfig{Threshold: 0.1, Debounce: time.Minute, Callback: func(TunnelingAlert) { callbacks.Add(1) }})
	start := time.Unix(1234, 5678)
	first := detector.AnalyzeAt(tunnelingObservation("example.test"), "hunter-a", "192.0.2.3", start)
	require.NotNil(t, first.Alert)
	require.True(t, first.AboveThreshold)
	require.False(t, first.Suppressed)
	require.Equal(t, start, first.Alert.Timestamp)
	require.Equal(t, first.Threshold, first.Alert.Threshold)
	require.Equal(t, first.Score, first.Alert.Score)
	require.Equal(t, first.Entropy, first.Alert.Entropy)

	response := tunnelingObservation("example.test")
	response.IsResponse = true
	second := detector.AnalyzeAt(response, "hunter-b", "192.0.2.1", start.Add(time.Minute-time.Nanosecond))
	require.Nil(t, second.Alert)
	require.True(t, second.AboveThreshold)
	require.True(t, second.Suppressed)
	require.Equal(t, first.Score, second.Score, "responses retain the historical scoring/counting behavior")
	boundary := detector.AnalyzeAt(tunnelingObservation("example.test"), "", "192.0.2.2", start.Add(time.Minute))
	require.NotNil(t, boundary.Alert, "debounce expires exactly at its configured boundary")
	require.Equal(t, int64(3), boundary.Alert.Queries)
	require.Equal(t, "local", boundary.Alert.HunterID)
	require.Equal(t, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, boundary.Alert.SrcIPs)
	require.Equal(t, uint64(0), detector.Stats().CallbackQueued)
	require.Equal(t, uint64(0), callbacks.Load())
	require.Equal(t, uint64(2), detector.Stats().Alerts)
	require.Equal(t, uint64(1), detector.Stats().Suppressed)
	require.Nil(t, detector.cleanupTicker, "clocked analysis owns no wall-clock janitor")
}

func TestAnalyzeAtWithoutCallbackConfigurationReturnsDecisions(t *testing.T) {
	detector := NewTunnelingDetector(clockedTunnelingConfig())
	t.Cleanup(detector.Stop)
	decision := detector.AnalyzeAt(tunnelingObservation("example.test"), "hunter", "192.0.2.1", time.Unix(100, 0))
	require.Equal(t, 0.7, decision.Threshold)
	require.Nil(t, detector.callbacks, "synchronous decisions do not create callback workers")
	detector.SetAlertConfig(AlertConfig{Threshold: 0.1})
	decision = detector.AnalyzeAt(tunnelingObservation("other.test"), "hunter", "192.0.2.1", time.Unix(100, 0))
	require.NotNil(t, decision.Alert)
	require.Nil(t, detector.callbacks, "a threshold-only configuration does not opt into callbacks")
	require.Equal(t, TunnelingDecision{}, detector.AnalyzeAt(nil, "", "", time.Time{}))
	require.Equal(t, TunnelingDecision{}, detector.AnalyzeAt(&types.DNSMetadata{}, "", "", time.Time{}))
}

func TestAnalyzeAtBoundsEvidenceAndReportsTruncation(t *testing.T) {
	config := clockedTunnelingConfig()
	config.MaxTrackedSubdomains, config.MaxSourceIPs = 2, 2
	detector := NewTunnelingDetector(config)
	t.Cleanup(detector.Stop)
	detector.SetAlertConfig(AlertConfig{}) // Explicit zero preserves the legacy threshold/debounce semantics.
	at := time.Unix(100, 0)
	var decision TunnelingDecision
	for i := 0; i < 6; i++ {
		observation := &types.DNSMetadata{QueryName: fmt.Sprintf("%02dabcdefghijklmnopqrstuvwxyz.example.test", i), QueryType: "TXT", IsResponse: i%2 == 1}
		decision = detector.AnalyzeAt(observation, "hunter", fmt.Sprintf("192.0.2.%d", 6-i), at)
	}
	require.NotNil(t, decision.Alert)
	require.Equal(t, int64(6), decision.Alert.Queries)
	require.Equal(t, 2, decision.Alert.UniqueSubdomains)
	require.True(t, decision.Alert.UniqueSubdomainsTruncated)
	require.True(t, decision.Alert.SrcIPsTruncated)
	require.Equal(t, []string{"192.0.2.5", "192.0.2.6"}, decision.Alert.SrcIPs)
	require.Equal(t, 2, detector.Stats().TrackedSubdomains)
	require.Equal(t, 2, detector.Stats().SourceIPs)

	reports := detector.GetSuspiciousDomains(0, 10)
	require.Len(t, reports, 1)
	require.Equal(t, 2, reports[0].UniqueSubdomains)
	require.True(t, reports[0].UniqueSubdomainsTruncated)
	require.True(t, reports[0].SrcIPsTruncated)
	require.Equal(t, decision.Alert.SrcIPs, reports[0].SrcIPs)
	// Returned evidence is independently owned by each consumer.
	decision.Alert.SrcIPs[0] = "modified"
	reports[0].SrcIPs[0] = "modified"
	require.Equal(t, []string{"192.0.2.5", "192.0.2.6"}, detector.GetSuspiciousDomains(0, 10)[0].SrcIPs)
}

func TestTunnelingDefaultEvidenceCapPreservesScoreSaturation(t *testing.T) {
	config := clockedTunnelingConfig()
	bounded := NewTunnelingDetector(config)
	t.Cleanup(bounded.Stop)
	config.MaxTrackedSubdomains = 1000
	reference := NewTunnelingDetector(config)
	t.Cleanup(reference.Stop)
	for i := 0; i < 150; i++ {
		name := fmt.Sprintf("%03dabcdefghijklmnopqrstuvwxyz0123456789.example.test", i)
		left, right := &types.DNSMetadata{QueryName: name, QueryType: "TXT"}, &types.DNSMetadata{QueryName: name, QueryType: "TXT"}
		bounded.AnalyzeAt(left, "", "", time.Unix(int64(i), 0))
		reference.AnalyzeAt(right, "", "", time.Unix(int64(i), 0))
		require.Equal(t, right.TunnelingScore, left.TunnelingScore, "capping after uniqueness saturation must preserve scores")
	}
	require.Equal(t, 100, bounded.Stats().TrackedSubdomains)
	require.Equal(t, 150, reference.Stats().TrackedSubdomains)
	require.True(t, bounded.GetSuspiciousDomains(0, 1)[0].UniqueSubdomainsTruncated)
	config.MaxUniqueSubdomains, config.MaxTrackedSubdomains = 250, 0
	adapted := NewTunnelingDetector(config)
	t.Cleanup(adapted.Stop)
	require.GreaterOrEqual(t, adapted.config.MaxTrackedSubdomains, config.MaxUniqueSubdomains)
}

func TestTunnelingEvictionExpiryAndEvidenceCleanupAreDeterministic(t *testing.T) {
	config := clockedTunnelingConfig()
	config.MaxDomains, config.MaxAge = 2, 10*time.Second
	detector := NewTunnelingDetector(config)
	t.Cleanup(detector.Stop)
	detector.SetAlertConfig(AlertConfig{Debounce: time.Minute})
	start := time.Unix(100, 0)
	for _, domain := range []string{"b.test", "a.test"} {
		require.NotNil(t, detector.AnalyzeAt(tunnelingObservation(domain), "", "192.0.2.1", start).Alert)
	}
	detector.AnalyzeAt(tunnelingObservation("c.test"), "", "192.0.2.2", start.Add(time.Second))
	require.NotContains(t, detector.domainStats, tunnelingDomainKey{domain: "a.test"}, "equal-age capacity eviction breaks ties by domain")
	require.NotContains(t, detector.srcIPs, tunnelingDomainKey{domain: "a.test"})
	require.NotContains(t, detector.lastAlerted, tunnelingDomainKey{domain: "a.test"})
	require.Len(t, detector.domainStats, 2)
	detector.AnalyzeAt(tunnelingObservation("c.test"), "", "192.0.2.2", start.Add(-time.Second))
	require.Equal(t, start.Add(time.Second), detector.domainStats[tunnelingDomainKey{domain: "c.test"}].LastSeen, "late input cannot move retention backwards")
	detector.Expire(start.Add(10 * time.Second))
	require.Contains(t, detector.domainStats, tunnelingDomainKey{domain: "b.test"}, "the exact MaxAge boundary preserves prior cleanup semantics")
	detector.Expire(start.Add(11*time.Second + time.Nanosecond))
	require.Zero(t, detector.Stats().Domains)
	require.Zero(t, detector.Stats().SourceIPs)
	require.Empty(t, detector.lastAlerted)
	recreated := detector.AnalyzeAt(tunnelingObservation("b.test"), "", "192.0.2.3", start.Add(12*time.Second))
	require.NotNil(t, recreated.Alert)
	require.Equal(t, int64(1), recreated.Alert.Queries)
	require.Equal(t, []string{"192.0.2.3"}, recreated.Alert.SrcIPs)
	// Direct observation also replaces an aged domain even without a janitor tick.
	recreated = detector.AnalyzeAt(tunnelingObservation("b.test"), "", "192.0.2.4", start.Add(23*time.Second))
	require.NotNil(t, recreated.Alert)
	require.Equal(t, int64(1), recreated.Alert.Queries)
	require.Equal(t, []string{"192.0.2.4"}, recreated.Alert.SrcIPs)
}

func TestTunnelingReportsHaveStableTiesAndEntropy(t *testing.T) {
	detector := NewTunnelingDetector(clockedTunnelingConfig())
	t.Cleanup(detector.Stop)
	for _, domain := range []string{"c.test", "b.test", "a.test"} {
		detector.AnalyzeAt(tunnelingObservation(domain), "", "", time.Unix(100, 0))
	}
	for range 20 {
		reports := detector.GetSuspiciousDomains(0, 2)
		require.Len(t, reports, 2)
		require.Equal(t, "a.test", reports[0].Domain)
		require.Equal(t, "b.test", reports[1].Domain)
	}
	require.Empty(t, detector.GetSuspiciousDomains(0, 0))
	require.Empty(t, detector.GetSuspiciousDomains(0, -1))
	want := calculateEntropy("aabbcccddddeeeeeffffff.0123456789.example.test")
	for range 100 {
		require.Equal(t, want, calculateEntropy("aabbcccddddeeeeeffffff.0123456789.example.test"))
	}
}

func TestAnalyzeScopedAtSeparatesEvidenceAndDebounceUnderOneBudget(t *testing.T) {
	config := clockedTunnelingConfig()
	config.MaxDomains, config.MaxUniqueSubdomains = 2, 20
	config.EntropyThreshold = 100 // Isolate the existing uniqueness score factor.
	detector := NewTunnelingDetector(config)
	t.Cleanup(detector.Stop)
	detector.SetAlertConfig(AlertConfig{Threshold: 0.1, Debounce: time.Minute})
	at := time.Unix(100, 0)
	observe := func(scope, address string, number int) TunnelingDecision {
		return detector.AnalyzeScopedAt(&types.DNSMetadata{QueryName: fmt.Sprintf("q%02d.example.test", number), QueryType: "A"}, "hunter", address, at, scope)
	}
	var first TunnelingDecision
	for i := 0; i < 11; i++ {
		first = observe("capture-a", "192.0.2.1", i)
	}
	require.NotNil(t, first.Alert)
	require.Equal(t, "example.test", first.Alert.Domain)
	second := observe("capture-b", "192.0.2.2", 99)
	require.Zero(t, second.Score, "another scope must not inherit uniqueness evidence")
	require.False(t, second.Suppressed)
	for i := 0; i < 10; i++ {
		second = observe("capture-b", "192.0.2.2", i)
	}
	require.NotNil(t, second.Alert, "another scope must not inherit the first scope's debounce")
	require.Equal(t, int64(11), second.Alert.Queries)
	require.Equal(t, []string{"192.0.2.2"}, second.Alert.SrcIPs)
	require.True(t, observe("capture-a", "192.0.2.1", 10).Suppressed)
	reports := detector.GetSuspiciousDomains(0, 10)
	require.Len(t, reports, 2)
	require.Equal(t, "example.test", reports[0].Domain)
	require.Equal(t, "example.test", reports[1].Domain)
	require.Equal(t, []string{"192.0.2.1"}, reports[0].SrcIPs)
	require.Equal(t, []string{"192.0.2.2"}, reports[1].SrcIPs)
	observe("capture-c", "192.0.2.3", 0)
	require.Equal(t, 2, detector.Stats().Domains, "scope cardinality shares the configured global budget")
	require.NotContains(t, detector.domainStats, tunnelingDomainKey{scope: "capture-a", domain: "example.test"})
	require.Len(t, detector.srcIPs, 2)
	require.LessOrEqual(t, len(detector.lastAlerted), 2)
}

func TestTunnelingCallbackQueueIsBoundedAndStopJoins(t *testing.T) {
	config := clockedTunnelingConfig()
	config.CallbackQueueSize = 1
	detector := NewTunnelingDetector(config)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); detector.Stop() })
	var delivered atomic.Uint64
	detector.SetAlertConfig(AlertConfig{Callback: func(TunnelingAlert) {
		if delivered.Add(1) == 1 {
			close(started)
		}
		<-release
	}})
	detector.AnalyzeWithContext(tunnelingObservation("first.test"), "", "")
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("callback worker did not enter")
	}
	detector.AnalyzeWithContext(tunnelingObservation("second.test"), "", "")
	detector.AnalyzeWithContext(tunnelingObservation("third.test"), "", "")
	require.Equal(t, uint64(2), detector.Stats().CallbackQueued)
	require.Equal(t, uint64(1), detector.Stats().CallbackDrops)
	stopped := make(chan struct{})
	go func() { detector.Stop(); close(stopped) }()
	require.Eventually(t, func() bool { return detector.Stats().Stopped }, 5*time.Second, time.Millisecond)
	select {
	case <-stopped:
		t.Fatal("Stop returned before its callback worker completed")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop failed to join its callback worker")
	}
	require.Equal(t, uint64(2), delivered.Load())
	require.Equal(t, uint64(2), detector.Stats().CallbackDelivered)
	detector.Stop()
	detector.SetAlertConfig(AlertConfig{Callback: func(TunnelingAlert) { t.Error("callback after Stop") }})
	require.True(t, detector.AnalyzeAt(tunnelingObservation("after.test"), "", "", time.Now()).Stopped)
	require.Equal(t, uint64(2), detector.Stats().CallbackQueued)
}

func TestTunnelingConcurrentStopAnalysisAndConfiguration(t *testing.T) {
	config := DefaultTunnelingConfig()
	config.CleanupInterval = time.Millisecond
	detector := NewTunnelingDetector(config)
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				detector.SetAlertConfig(AlertConfig{Callback: func(TunnelingAlert) {}})
				detector.AnalyzeWithContext(tunnelingObservation("concurrent.test"), "", "192.0.2.1")
				detector.Stats()
			}
		})
	}
	for range 4 {
		workers.Go(detector.Stop)
	}
	workers.Wait()
	detector.Stop()
	require.True(t, detector.Stats().Stopped)
	require.Equal(t, detector.Stats().CallbackQueued, detector.Stats().CallbackDelivered)
}
