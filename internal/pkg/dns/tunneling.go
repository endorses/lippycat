package dns

import (
	"math"
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
	Queries   int64
	SrcIPs    []string
	HunterID  string
	Timestamp time.Time
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
	domainStats   map[string]*domainStats
	config        TunnelingConfig
	maxDomains    int
	cleanupTicker *time.Ticker

	// Alert tracking
	alertConfig *AlertConfig
	lastAlerted map[string]time.Time           // Last alert time per domain
	srcIPs      map[string]map[string]struct{} // Source IPs per domain
}

// domainStats tracks statistics for a domain to detect tunneling.
type domainStats struct {
	BaseDomain       string
	SubdomainCount   int64
	TotalQueryLength int64
	QueryCount       int64
	UniqueSubdomains map[string]struct{}
	HighEntropyCount int64
	TXTQueryCount    int64
	NULLQueryCount   int64
	LastSeen         time.Time
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
	if config.MaxUniqueSubdomains == 0 {
		config.MaxUniqueSubdomains = 100
	}
	if len(config.SuspiciousRecordTypes) == 0 {
		config.SuspiciousRecordTypes = []string{"TXT", "NULL", "CNAME"}
	}
	if config.MaxDomains == 0 {
		config.MaxDomains = 5000
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.MaxAge == 0 {
		config.MaxAge = 1 * time.Hour
	}

	td := &TunnelingDetector{
		domainStats:   make(map[string]*domainStats),
		config:        config,
		maxDomains:    config.MaxDomains,
		cleanupTicker: time.NewTicker(config.CleanupInterval),
		lastAlerted:   make(map[string]time.Time),
		srcIPs:        make(map[string]map[string]struct{}),
	}

	go td.cleanupLoop()

	return td
}

// SetAlertConfig configures alert behavior for the detector.
// When set, the detector will call the callback when a domain's tunneling
// score crosses the threshold, respecting the debounce interval.
func (td *TunnelingDetector) SetAlertConfig(config AlertConfig) {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.alertConfig = &config
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
	if metadata == nil || metadata.QueryName == "" {
		return
	}

	// Calculate entropy for the query name
	entropy := calculateEntropy(metadata.QueryName)
	metadata.EntropyScore = entropy

	// Extract base domain and subdomain
	baseDomain, subdomain := extractDomainParts(metadata.QueryName)
	if baseDomain == "" {
		return
	}

	td.mu.Lock()
	defer td.mu.Unlock()

	stats, exists := td.domainStats[baseDomain]
	if !exists {
		if len(td.domainStats) >= td.maxDomains {
			td.evictOldest()
		}
		stats = &domainStats{
			BaseDomain:       baseDomain,
			UniqueSubdomains: make(map[string]struct{}),
		}
		td.domainStats[baseDomain] = stats
	}

	// Update statistics
	stats.QueryCount++
	stats.TotalQueryLength += int64(len(metadata.QueryName))
	stats.LastSeen = time.Now()

	if subdomain != "" {
		stats.SubdomainCount++
		stats.UniqueSubdomains[subdomain] = struct{}{}

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
		if td.srcIPs[baseDomain] == nil {
			td.srcIPs[baseDomain] = make(map[string]struct{})
		}
		td.srcIPs[baseDomain][srcIP] = struct{}{}
	}

	// Calculate tunneling score
	metadata.TunnelingScore = td.calculateScore(stats, metadata)

	// Check alert threshold and debounce
	td.checkAndTriggerAlert(baseDomain, stats, metadata, hunterID)
}

// checkAndTriggerAlert checks if an alert should be triggered for the domain.
// Must be called with td.mu held.
func (td *TunnelingDetector) checkAndTriggerAlert(baseDomain string, stats *domainStats, metadata *types.DNSMetadata, hunterID string) {
	if td.alertConfig == nil || td.alertConfig.Callback == nil {
		return
	}

	// Check if score crosses threshold
	if metadata.TunnelingScore < td.alertConfig.Threshold {
		return
	}

	// Check debounce
	lastTime, exists := td.lastAlerted[baseDomain]
	if exists && time.Since(lastTime) < td.alertConfig.Debounce {
		return
	}

	// Update last alerted time
	td.lastAlerted[baseDomain] = time.Now()

	// Build source IPs list
	var srcIPsList []string
	if ips, ok := td.srcIPs[baseDomain]; ok {
		srcIPsList = make([]string, 0, len(ips))
		for ip := range ips {
			srcIPsList = append(srcIPsList, ip)
		}
	}

	// Use "local" as default hunter ID if not provided
	if hunterID == "" {
		hunterID = "local"
	}

	// Create alert
	alert := TunnelingAlert{
		Domain:    baseDomain,
		Score:     metadata.TunnelingScore,
		Entropy:   metadata.EntropyScore,
		Queries:   stats.QueryCount,
		SrcIPs:    srcIPsList,
		HunterID:  hunterID,
		Timestamp: time.Now(),
	}

	// Call callback in a goroutine to avoid blocking
	callback := td.alertConfig.Callback
	go callback(alert)
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
	for _, count := range freq {
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
	var oldestKey string
	var oldestTime time.Time

	for k, v := range td.domainStats {
		if oldestKey == "" || v.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.LastSeen
		}
	}

	if oldestKey != "" {
		delete(td.domainStats, oldestKey)
	}
}

// cleanupLoop periodically removes old domain stats.
func (td *TunnelingDetector) cleanupLoop() {
	for range td.cleanupTicker.C {
		td.cleanup()
	}
}

// cleanup removes entries older than MaxAge.
func (td *TunnelingDetector) cleanup() {
	cutoff := time.Now().Add(-td.config.MaxAge)

	td.mu.Lock()
	defer td.mu.Unlock()

	for k, v := range td.domainStats {
		if v.LastSeen.Before(cutoff) {
			delete(td.domainStats, k)
			// Also clean up related tracking data
			delete(td.srcIPs, k)
			delete(td.lastAlerted, k)
		}
	}
}

// Stop stops the tunneling detector.
func (td *TunnelingDetector) Stop() {
	td.cleanupTicker.Stop()
}

// TunnelingReport represents a tunneling detection report.
type TunnelingReport struct {
	Domain             string
	Score              float64
	QueryCount         int64
	UniqueSubdomains   int
	HighEntropyQueries int64
	TXTQueries         int64
	AvgQueryLength     float64
	Indicators         []string
}

// GetSuspiciousDomains returns domains with high tunneling scores.
func (td *TunnelingDetector) GetSuspiciousDomains(threshold float64, limit int) []TunnelingReport {
	td.mu.RLock()
	defer td.mu.RUnlock()

	var reports []TunnelingReport
	for _, stats := range td.domainStats {
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
			Domain:             stats.BaseDomain,
			QueryCount:         stats.QueryCount,
			UniqueSubdomains:   len(stats.UniqueSubdomains),
			HighEntropyQueries: stats.HighEntropyCount,
			TXTQueries:         stats.TXTQueryCount,
			AvgQueryLength:     avgLength,
			Indicators:         indicators,
		}

		// Simple score estimation
		report.Score = float64(len(indicators)) * 0.25
		if report.Score > 1.0 {
			report.Score = 1.0
		}

		if report.Score >= threshold {
			reports = append(reports, report)
		}
	}

	// Sort by score (simple selection)
	for i := 0; i < len(reports) && i < limit; i++ {
		maxIdx := i
		for j := i + 1; j < len(reports); j++ {
			if reports[j].Score > reports[maxIdx].Score {
				maxIdx = j
			}
		}
		reports[i], reports[maxIdx] = reports[maxIdx], reports[i]
	}

	if limit > len(reports) {
		limit = len(reports)
	}
	return reports[:limit]
}
