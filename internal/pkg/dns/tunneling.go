package dns

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// TunnelingAlert represents an alert for detected DNS tunneling.
type TunnelingAlert struct {
	Domain    string
	Score     float64
	Entropy   float64
	Queries   int64 // DNS observations, including responses, as in the legacy detector.
	SrcIPs    []string
	HunterID  string
	Timestamp time.Time
	Threshold float64
	// UniqueSubdomains is the retained distinct count, a lower bound when
	// UniqueSubdomainsTruncated is true. SrcIPs is likewise bounded evidence.
	UniqueSubdomains          int
	UniqueSubdomainsTruncated bool
	SrcIPsTruncated           bool
}

// TunnelingDecision is the synchronous result of one DNS observation. Suppressed
// means the score reached Threshold but observation-clock debounce withheld an
// alert. AnalyzeAt never invokes or queues a callback.
type TunnelingDecision struct {
	Alert          *TunnelingAlert
	Domain         string
	Score          float64
	Entropy        float64
	Threshold      float64
	AboveThreshold bool
	Suppressed     bool
	Stopped        bool
}

// TunnelingStats reports retained evidence and callback delivery pressure.
type TunnelingStats struct {
	Domains, TrackedSubdomains, SourceIPs            int
	Alerts, Suppressed                               uint64
	CallbackQueued, CallbackDelivered, CallbackDrops uint64
	Stopped                                          bool
}

type tunnelingCallback struct {
	alert    TunnelingAlert
	callback func(TunnelingAlert)
}

// One scoped key owns all evidence and debounce state under the detector's
// global domain budget. Distinct capture domains cannot share a finding.
type tunnelingDomainKey struct {
	scope  string
	domain string
}

func (key tunnelingDomainKey) less(other tunnelingDomainKey) bool {
	if key.domain != other.domain {
		return key.domain < other.domain
	}
	return key.scope < other.scope
}

// AlertConfig configures alert behavior for tunneling detection.
type AlertConfig struct {
	Threshold float64                    // Score threshold (default: 0.7)
	Debounce  time.Duration              // Min time between alerts per domain (default: 5m)
	Callback  func(alert TunnelingAlert) // Callback when alert triggers
}

// TunnelingDetector detects potential DNS tunneling attempts.
type TunnelingDetector struct {
	mu            sync.RWMutex
	domainStats   map[tunnelingDomainKey]*domainStats
	config        TunnelingConfig
	maxDomains    int
	cleanupTicker *time.Ticker
	stop          chan struct{}
	stopOnce      sync.Once
	wg            sync.WaitGroup
	stopped       bool
	callbacks     chan tunnelingCallback
	stats         TunnelingStats

	// Alert tracking
	alertConfig *AlertConfig
	lastAlerted map[tunnelingDomainKey]time.Time           // Last alert time per scoped domain
	srcIPs      map[tunnelingDomainKey]map[string]struct{} // Source IPs per scoped domain
}

// domainStats tracks statistics for a domain to detect tunneling.
type domainStats struct {
	BaseDomain                string
	SubdomainCount            int64
	TotalQueryLength          int64
	QueryCount                int64
	UniqueSubdomains          map[string]struct{}
	HighEntropyCount          int64
	TXTQueryCount             int64
	NULLQueryCount            int64
	LastSeen                  time.Time
	UniqueSubdomainsTruncated bool
	SrcIPsTruncated           bool
}

// TunnelingConfig holds configuration for tunneling detection.
type TunnelingConfig struct {
	// EntropyThreshold is the Shannon entropy threshold for considering
	// a subdomain as potentially encoded data. Default: 3.5
	EntropyThreshold float64

	// MinSubdomainLength is the minimum subdomain length to analyze.
	// Shorter subdomains are likely legitimate. Default: 20
	MinSubdomainLength int

	// MaxUniqueSubdomains is the threshold for unique subdomains before
	// flagging as suspicious. Default: 100
	MaxUniqueSubdomains int

	// SuspiciousRecordTypes are record types often used for tunneling.
	// Default: TXT, NULL, CNAME
	SuspiciousRecordTypes []string

	// MaxDomains is the maximum number of domains to track. Default: 5000
	MaxDomains int

	// CleanupInterval is how often to clean up old entries. Default: 5 minutes
	CleanupInterval time.Duration

	// MaxAge is the maximum age for domain stats. Default: 1 hour
	MaxAge time.Duration

	// DisableJanitor makes expiry entirely observation-clock driven through
	// Expire. Canonical and offline runtimes should enable this option.
	DisableJanitor bool

	// MaxTrackedSubdomains bounds distinct evidence per domain. Zero selects
	// max(100, MaxUniqueSubdomains, 11), retaining score saturation by default.
	// A smaller explicit cap can understate uniqueness scores; truncation is
	// reported in alerts and reports instead of claiming an exact total.
	MaxTrackedSubdomains int
	// MaxSourceIPs bounds retained source addresses per domain. Default: 64.
	MaxSourceIPs int
	// CallbackQueueSize bounds pending legacy callbacks. Default: 128.
	CallbackQueueSize int
}

// DefaultTunnelingConfig returns the default tunneling detection configuration.
func DefaultTunnelingConfig() TunnelingConfig {
	return TunnelingConfig{
		EntropyThreshold:      3.5,
		MinSubdomainLength:    20,
		MaxUniqueSubdomains:   100,
		SuspiciousRecordTypes: []string{"TXT", "NULL", "CNAME"},
		MaxDomains:            5000,
		CleanupInterval:       5 * time.Minute,
		MaxAge:                1 * time.Hour,
		MaxSourceIPs:          64,
		CallbackQueueSize:     128,
	}
}

// NewTunnelingDetector creates a new tunneling detector.
func NewTunnelingDetector(config TunnelingConfig) *TunnelingDetector {
	if config.EntropyThreshold == 0 {
		config.EntropyThreshold = 3.5
	}
	if config.MinSubdomainLength == 0 {
		config.MinSubdomainLength = 20
	}
	if config.MaxUniqueSubdomains <= 0 {
		config.MaxUniqueSubdomains = 100
	}
	if len(config.SuspiciousRecordTypes) == 0 {
		config.SuspiciousRecordTypes = []string{"TXT", "NULL", "CNAME"}
	}
	if config.MaxDomains <= 0 {
		config.MaxDomains = 5000
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.MaxAge <= 0 {
		config.MaxAge = 1 * time.Hour
	}
	if config.MaxTrackedSubdomains <= 0 {
		config.MaxTrackedSubdomains = max(100, config.MaxUniqueSubdomains, 11)
	}
	if config.MaxSourceIPs <= 0 {
		config.MaxSourceIPs = 64
	}
	if config.CallbackQueueSize <= 0 {
		config.CallbackQueueSize = 128
	}
	config.SuspiciousRecordTypes = append([]string(nil), config.SuspiciousRecordTypes...)

	td := &TunnelingDetector{
		domainStats: make(map[tunnelingDomainKey]*domainStats),
		config:      config,
		maxDomains:  config.MaxDomains,
		stop:        make(chan struct{}),
		lastAlerted: make(map[tunnelingDomainKey]time.Time),
		srcIPs:      make(map[tunnelingDomainKey]map[string]struct{}),
	}

	if !config.DisableJanitor {
		td.cleanupTicker = time.NewTicker(config.CleanupInterval)
		td.wg.Add(1)
		go td.cleanupLoop()
	}

	return td
}

// SetAlertConfig configures threshold/debounce decisions, preserving explicit
// zero values. A nonnil Callback opts legacy Analyze calls into bounded delivery;
// synchronous AnalyzeAt callers should leave it nil.
func (td *TunnelingDetector) SetAlertConfig(config AlertConfig) {
	td.mu.Lock()
	defer td.mu.Unlock()
	if td.stopped {
		return
	}
	td.alertConfig = &config
	if config.Callback != nil && td.callbacks == nil {
		td.callbacks = make(chan tunnelingCallback, td.config.CallbackQueueSize)
		td.wg.Add(1)
		go td.callbackLoop()
	}
}

// Analyze analyzes a DNS query for tunneling indicators.
// Updates the metadata with tunneling score and entropy.
// For backward compatibility; use AnalyzeWithContext for full alerting support.
func (td *TunnelingDetector) Analyze(metadata *types.DNSMetadata) {
	td.AnalyzeWithContext(metadata, "", "")
}

// AnalyzeWithContext analyzes a DNS query for tunneling indicators with context.
// hunterID identifies the source hunter (or "local" for tap mode).
// srcIP is the source IP address of the DNS query.
// Updates the metadata with tunneling score and entropy.
// Triggers alerts when score crosses threshold (if alertConfig is set).
func (td *TunnelingDetector) AnalyzeWithContext(metadata *types.DNSMetadata, hunterID, srcIP string) {
	td.analyzeAt(metadata, hunterID, srcIP, time.Now(), true, "")
}

// AnalyzeAt analyzes queries and responses using their observation time. It
// updates metadata and returns threshold/debounce evidence without delivering
// callbacks, even if a callback has been configured for legacy callers.
func (td *TunnelingDetector) AnalyzeAt(metadata *types.DNSMetadata, hunterID, srcIP string, observedAt time.Time) TunnelingDecision {
	return td.AnalyzeScopedAt(metadata, hunterID, srcIP, observedAt, "")
}

// AnalyzeScopedAt isolates evidence and debounce by capture scope while retaining
// one global domain/evidence budget. Alert Domain remains the actual DNS domain.
func (td *TunnelingDetector) AnalyzeScopedAt(metadata *types.DNSMetadata, hunterID, srcIP string, observedAt time.Time, scope string) TunnelingDecision {
	return td.analyzeAt(metadata, hunterID, srcIP, observedAt, false, scope)
}

func (td *TunnelingDetector) analyzeAt(metadata *types.DNSMetadata, hunterID, srcIP string, observedAt time.Time, legacyCallback bool, scope string) TunnelingDecision {
	if metadata == nil || metadata.QueryName == "" {
		return TunnelingDecision{}
	}

	// Calculate entropy for the query name
	entropy := calculateEntropy(metadata.QueryName)
	metadata.EntropyScore = entropy

	// Extract base domain and subdomain
	baseDomain, subdomain := extractDomainParts(metadata.QueryName)
	if baseDomain == "" {
		return TunnelingDecision{}
	}

	td.mu.Lock()
	defer td.mu.Unlock()
	if td.stopped {
		return TunnelingDecision{Stopped: true}
	}

	key := tunnelingDomainKey{scope: scope, domain: baseDomain}
	stats, exists := td.domainStats[key]
	if exists && stats.LastSeen.Before(observedAt.Add(-td.config.MaxAge)) {
		td.removeDomain(key)
		exists = false
	}
	if !exists {
		if len(td.domainStats) >= td.maxDomains {
			td.evictOldest()
		}
		stats = &domainStats{
			BaseDomain:       baseDomain,
			UniqueSubdomains: make(map[string]struct{}),
		}
		td.domainStats[key] = stats
	}

	// Update statistics
	stats.QueryCount++
	stats.TotalQueryLength += int64(len(metadata.QueryName))
	// Late observations may contribute evidence, but must not move retention
	// backwards or become fresh merely because replay happened later.
	if !exists || observedAt.After(stats.LastSeen) {
		stats.LastSeen = observedAt
	}

	if subdomain != "" {
		stats.SubdomainCount++
		if _, known := stats.UniqueSubdomains[subdomain]; !known {
			if len(stats.UniqueSubdomains) < td.config.MaxTrackedSubdomains {
				stats.UniqueSubdomains[subdomain] = struct{}{}
			} else {
				stats.UniqueSubdomainsTruncated = true
			}
		}

		// Check for high entropy subdomain
		if len(subdomain) >= td.config.MinSubdomainLength {
			subEntropy := calculateEntropy(subdomain)
			if subEntropy >= td.config.EntropyThreshold {
				stats.HighEntropyCount++
			}
		}
	}

	// Track suspicious record types
	for _, suspicious := range td.config.SuspiciousRecordTypes {
		if metadata.QueryType == suspicious {
			switch suspicious {
			case "TXT":
				stats.TXTQueryCount++
			case "NULL":
				stats.NULLQueryCount++
			}
		}
	}

	// Track source IP per domain
	if srcIP != "" {
		if td.srcIPs[key] == nil {
			td.srcIPs[key] = make(map[string]struct{})
		}
		if _, known := td.srcIPs[key][srcIP]; !known {
			if len(td.srcIPs[key]) < td.config.MaxSourceIPs {
				td.srcIPs[key][srcIP] = struct{}{}
			} else {
				stats.SrcIPsTruncated = true
			}
		}
	}

	// Calculate tunneling score
	metadata.TunnelingScore = td.calculateScore(stats, metadata)

	// Check alert threshold and debounce
	decision := td.decideAlert(key, stats, metadata, hunterID, observedAt, legacyCallback)
	if legacyCallback && decision.Alert != nil {
		select {
		case td.callbacks <- tunnelingCallback{alert: *decision.Alert, callback: td.alertConfig.Callback}:
			td.stats.CallbackQueued++
		default:
			td.stats.CallbackDrops++
		}
	}
	return decision
}

// decideAlert checks whether the observation triggers a threshold/debounce decision.
// Must be called with td.mu held.
func (td *TunnelingDetector) decideAlert(key tunnelingDomainKey, stats *domainStats, metadata *types.DNSMetadata, hunterID string, observedAt time.Time, legacyCallback bool) TunnelingDecision {
	config := AlertConfig{Threshold: 0.7, Debounce: 5 * time.Minute}
	if td.alertConfig != nil {
		config = *td.alertConfig
	}
	decision := TunnelingDecision{Domain: stats.BaseDomain, Score: metadata.TunnelingScore, Entropy: metadata.EntropyScore, Threshold: config.Threshold}
	decision.AboveThreshold = metadata.TunnelingScore >= config.Threshold
	if !decision.AboveThreshold || legacyCallback && config.Callback == nil {
		return decision
	}

	// Check debounce
	lastTime, exists := td.lastAlerted[key]
	if exists && observedAt.Sub(lastTime) < config.Debounce {
		decision.Suppressed = true
		td.stats.Suppressed++
		return decision
	}

	// Update last alerted time
	td.lastAlerted[key] = observedAt

	// Build source IPs list
	var srcIPsList []string
	if ips, ok := td.srcIPs[key]; ok {
		srcIPsList = make([]string, 0, len(ips))
		for ip := range ips {
			srcIPsList = append(srcIPsList, ip)
		}
		sort.Strings(srcIPsList)
	}

	// Use "local" as default hunter ID if not provided
	if hunterID == "" {
		hunterID = "local"
	}

	// Create alert
	decision.Alert = &TunnelingAlert{
		Domain:                    stats.BaseDomain,
		Score:                     metadata.TunnelingScore,
		Entropy:                   metadata.EntropyScore,
		Queries:                   stats.QueryCount,
		SrcIPs:                    srcIPsList,
		HunterID:                  hunterID,
		Timestamp:                 observedAt,
		Threshold:                 config.Threshold,
		UniqueSubdomains:          len(stats.UniqueSubdomains),
		UniqueSubdomainsTruncated: stats.UniqueSubdomainsTruncated,
		SrcIPsTruncated:           stats.SrcIPsTruncated,
	}
	td.stats.Alerts++
	return decision
}

func (td *TunnelingDetector) callbackLoop() {
	defer td.wg.Done()
	for job := range td.callbacks {
		job.callback(job.alert)
		td.mu.Lock()
		td.stats.CallbackDelivered++
		td.mu.Unlock()
	}
}

// calculateScore computes a tunneling probability score.
func (td *TunnelingDetector) calculateScore(stats *domainStats, metadata *types.DNSMetadata) float64 {
	var score float64

	// Factor 1: High entropy in query name (0-0.3)
	if metadata.EntropyScore >= td.config.EntropyThreshold {
		entropyFactor := (metadata.EntropyScore - td.config.EntropyThreshold) / 1.0
		if entropyFactor > 1.0 {
			entropyFactor = 1.0
		}
		score += entropyFactor * 0.3
	}

	// Factor 2: Many unique subdomains (0-0.25)
	if len(stats.UniqueSubdomains) > 10 {
		subdomainFactor := float64(len(stats.UniqueSubdomains)) / float64(td.config.MaxUniqueSubdomains)
		if subdomainFactor > 1.0 {
			subdomainFactor = 1.0
		}
		score += subdomainFactor * 0.25
	}

	// Factor 3: High proportion of high-entropy subdomains (0-0.2)
	if stats.SubdomainCount > 0 {
		highEntropyRatio := float64(stats.HighEntropyCount) / float64(stats.SubdomainCount)
		score += highEntropyRatio * 0.2
	}

	// Factor 4: Suspicious record types (0-0.15)
	suspiciousQueries := stats.TXTQueryCount + stats.NULLQueryCount
	if stats.QueryCount > 0 && suspiciousQueries > 0 {
		suspiciousRatio := float64(suspiciousQueries) / float64(stats.QueryCount)
		score += suspiciousRatio * 0.15
	}

	// Factor 5: Long query names (0-0.1)
	if stats.QueryCount > 0 {
		avgLength := float64(stats.TotalQueryLength) / float64(stats.QueryCount)
		if avgLength > 50 {
			lengthFactor := (avgLength - 50) / 100
			if lengthFactor > 1.0 {
				lengthFactor = 1.0
			}
			score += lengthFactor * 0.1
		}
	}

	// Normalize score to 0-1
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// calculateEntropy computes Shannon entropy of a string.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies (case-insensitive)
	freq := make(map[rune]int)
	total := 0
	for _, c := range strings.ToLower(s) {
		if c != '.' { // Ignore dots in domain names
			freq[c]++
			total++
		}
	}

	if total == 0 {
		return 0
	}

	// Calculate entropy
	var entropy float64
	characters := make([]rune, 0, len(freq))
	for character := range freq {
		characters = append(characters, character)
	}
	sort.Slice(characters, func(i, j int) bool { return characters[i] < characters[j] })
	for _, character := range characters {
		count := freq[character]
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// extractDomainParts extracts the base domain and subdomain from a FQDN.
// For example, "data.example.com" returns ("example.com", "data")
func extractDomainParts(fqdn string) (baseDomain, subdomain string) {
	// Remove trailing dot if present
	fqdn = strings.TrimSuffix(fqdn, ".")
	fqdn = strings.ToLower(fqdn)

	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return fqdn, ""
	}

	// Handle common TLDs (simple heuristic)
	// For proper handling, would need a public suffix list
	if len(parts) >= 2 {
		// Check for two-part TLDs like co.uk, com.au
		lastPart := parts[len(parts)-1]
		secondLast := parts[len(parts)-2]

		isTwoPartTLD := false
		twoPartTLDs := map[string]map[string]bool{
			"uk": {"co": true, "org": true, "ac": true, "gov": true},
			"au": {"com": true, "org": true, "net": true, "edu": true},
			"nz": {"co": true, "org": true, "net": true},
			"jp": {"co": true, "or": true, "ne": true, "ac": true},
		}
		if domains, ok := twoPartTLDs[lastPart]; ok {
			if domains[secondLast] {
				isTwoPartTLD = true
			}
		}

		if isTwoPartTLD && len(parts) >= 3 {
			baseDomain = strings.Join(parts[len(parts)-3:], ".")
			if len(parts) > 3 {
				subdomain = strings.Join(parts[:len(parts)-3], ".")
			}
		} else {
			baseDomain = strings.Join(parts[len(parts)-2:], ".")
			if len(parts) > 2 {
				subdomain = strings.Join(parts[:len(parts)-2], ".")
			}
		}
	}

	return baseDomain, subdomain
}

// IsSuspiciousName checks if a domain name has suspicious characteristics.
func IsSuspiciousName(name string) bool {
	// Check for unusual character patterns
	digitCount := 0
	letterCount := 0
	for _, c := range name {
		if unicode.IsDigit(c) {
			digitCount++
		} else if unicode.IsLetter(c) {
			letterCount++
		}
	}

	// High digit-to-letter ratio is suspicious
	if letterCount > 0 && float64(digitCount)/float64(letterCount) > 0.5 {
		return true
	}

	// Very long labels (without dots) are suspicious
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) > 50 {
			return true
		}
	}

	// Base64-like patterns (mix of upper/lower/digits)
	entropy := calculateEntropy(name)
	if entropy > 4.0 && len(name) > 30 {
		return true
	}

	return false
}

// evictOldest removes the oldest entry from domainStats.
func (td *TunnelingDetector) evictOldest() {
	var oldestKey tunnelingDomainKey
	var oldestTime time.Time
	found := false

	for k, v := range td.domainStats {
		if !found || v.LastSeen.Before(oldestTime) || v.LastSeen.Equal(oldestTime) && k.less(oldestKey) {
			oldestKey = k
			oldestTime = v.LastSeen
			found = true
		}
	}

	if found {
		td.removeDomain(oldestKey)
	}
}

func (td *TunnelingDetector) removeDomain(domain tunnelingDomainKey) {
	delete(td.domainStats, domain)
	delete(td.srcIPs, domain)
	delete(td.lastAlerted, domain)
}

// cleanupLoop periodically removes old domain stats.
func (td *TunnelingDetector) cleanupLoop() {
	defer td.wg.Done()
	defer td.cleanupTicker.Stop()
	for {
		select {
		case at := <-td.cleanupTicker.C:
			td.Expire(at)
		case <-td.stop:
			return
		}
	}
}

// cleanup removes entries older than MaxAge.
func (td *TunnelingDetector) cleanup() {
	td.Expire(time.Now())
}

// Expire removes evidence strictly older than MaxAge on the supplied observation
// clock. Entries exactly at the age boundary retain the existing cleanup semantics.
func (td *TunnelingDetector) Expire(at time.Time) {
	cutoff := at.Add(-td.config.MaxAge)
	td.mu.Lock()
	defer td.mu.Unlock()
	if td.stopped {
		return
	}

	for k, v := range td.domainStats {
		if v.LastSeen.Before(cutoff) {
			td.removeDomain(k)
		}
	}
}

// Stop joins the janitor and drains accepted legacy callbacks. Callbacks must
// return and must not call Stop themselves. No worker is created unless opted in.
func (td *TunnelingDetector) Stop() {
	td.stopOnce.Do(func() {
		td.mu.Lock()
		td.stopped = true
		close(td.stop)
		if td.callbacks != nil {
			close(td.callbacks)
		}
		td.mu.Unlock()
		td.wg.Wait()
	})
}

// Stats returns a race-safe snapshot of detector retention and callback pressure.
func (td *TunnelingDetector) Stats() TunnelingStats {
	td.mu.RLock()
	defer td.mu.RUnlock()
	stats := td.stats
	stats.Domains, stats.Stopped = len(td.domainStats), td.stopped
	for domain, evidence := range td.domainStats {
		stats.TrackedSubdomains += len(evidence.UniqueSubdomains)
		stats.SourceIPs += len(td.srcIPs[domain])
	}
	return stats
}

// TunnelingReport represents a tunneling detection report. UniqueSubdomains is
// the retained distinct count, a lower bound when UniqueSubdomainsTruncated is
// true. SrcIPs is the retained source evidence, incomplete when SrcIPsTruncated.
type TunnelingReport struct {
	Domain                    string
	Score                     float64
	QueryCount                int64
	UniqueSubdomains          int
	HighEntropyQueries        int64
	TXTQueries                int64
	AvgQueryLength            float64
	Indicators                []string
	UniqueSubdomainsTruncated bool
	SrcIPs                    []string
	SrcIPsTruncated           bool
}

// GetSuspiciousDomains returns domains with high tunneling scores.
func (td *TunnelingDetector) GetSuspiciousDomains(threshold float64, limit int) []TunnelingReport {
	td.mu.RLock()
	defer td.mu.RUnlock()
	if limit <= 0 {
		return nil
	}

	var reports []TunnelingReport
	keys := make([]tunnelingDomainKey, 0, len(td.domainStats))
	for key := range td.domainStats {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].less(keys[j]) })
	for _, key := range keys {
		stats := td.domainStats[key]
		// Recalculate score with a dummy metadata
		avgLength := float64(0)
		if stats.QueryCount > 0 {
			avgLength = float64(stats.TotalQueryLength) / float64(stats.QueryCount)
		}

		// Build indicators list
		var indicators []string
		if len(stats.UniqueSubdomains) > td.config.MaxUniqueSubdomains/2 {
			indicators = append(indicators, "many_subdomains")
		}
		if stats.HighEntropyCount > stats.SubdomainCount/2 && stats.SubdomainCount > 0 {
			indicators = append(indicators, "high_entropy")
		}
		if stats.TXTQueryCount > stats.QueryCount/4 && stats.QueryCount > 0 {
			indicators = append(indicators, "txt_heavy")
		}
		if avgLength > 80 {
			indicators = append(indicators, "long_queries")
		}

		if len(indicators) == 0 {
			continue
		}

		report := TunnelingReport{
			Domain:                    stats.BaseDomain,
			QueryCount:                stats.QueryCount,
			UniqueSubdomains:          len(stats.UniqueSubdomains),
			HighEntropyQueries:        stats.HighEntropyCount,
			TXTQueries:                stats.TXTQueryCount,
			AvgQueryLength:            avgLength,
			Indicators:                indicators,
			UniqueSubdomainsTruncated: stats.UniqueSubdomainsTruncated,
			SrcIPsTruncated:           stats.SrcIPsTruncated,
		}
		for ip := range td.srcIPs[key] {
			report.SrcIPs = append(report.SrcIPs, ip)
		}
		sort.Strings(report.SrcIPs)

		// Simple score estimation
		report.Score = float64(len(indicators)) * 0.25
		if report.Score > 1.0 {
			report.Score = 1.0
		}

		if report.Score >= threshold {
			reports = append(reports, report)
		}
	}

	sort.SliceStable(reports, func(i, j int) bool {
		if reports[i].Score != reports[j].Score {
			return reports[i].Score > reports[j].Score
		}
		return reports[i].Domain < reports[j].Domain
	})

	if limit > len(reports) {
		limit = len(reports)
	}
	return reports[:limit]
}
