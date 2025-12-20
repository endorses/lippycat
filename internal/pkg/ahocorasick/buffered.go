package ahocorasick

import (
	"bytes"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// BufferedMatcher provides a double-buffered Aho-Corasick matcher for lock-free reads
// and background rebuilds. This enables zero-downtime pattern updates in high-throughput
// environments like network traffic analysis.
//
// Key features:
//   - Lock-free reads via atomic.Pointer for minimal latency
//   - Background automaton rebuilds without blocking matches
//   - Linear scan fallback during initial build or when automaton is unavailable
//   - Thread-safe pattern updates
type BufferedMatcher struct {
	// automaton is the current Aho-Corasick automaton, accessed atomically.
	// nil indicates no automaton is available (use linear scan fallback).
	automaton atomic.Pointer[AhoCorasick]

	// patterns stores the current pattern list for linear scan fallback
	// and for rebuilding the automaton.
	patterns []Pattern

	// patternsMu protects patterns slice during updates.
	patternsMu sync.RWMutex

	// buildMu ensures only one rebuild runs at a time.
	buildMu sync.Mutex

	// building indicates a rebuild is in progress.
	building atomic.Bool

	// lastBuildTime tracks when the automaton was last built.
	lastBuildTime atomic.Value // time.Time

	// lastBuildDuration tracks how long the last build took.
	lastBuildDuration atomic.Value // time.Duration
}

// NewBufferedMatcher creates a new BufferedMatcher.
func NewBufferedMatcher() *BufferedMatcher {
	bm := &BufferedMatcher{}
	bm.lastBuildTime.Store(time.Time{})
	bm.lastBuildDuration.Store(time.Duration(0))
	return bm
}

// UpdatePatterns updates the pattern list and triggers a background rebuild.
// This method is safe to call concurrently with Match operations.
// During the rebuild, Match will continue using the old automaton (or linear scan
// if no automaton exists yet).
func (bm *BufferedMatcher) UpdatePatterns(patterns []Pattern) {
	bm.patternsMu.Lock()
	bm.patterns = make([]Pattern, len(patterns))
	copy(bm.patterns, patterns)
	bm.patternsMu.Unlock()

	// Trigger background rebuild
	go bm.rebuildAutomaton()
}

// UpdatePatternsSync updates patterns and waits for the rebuild to complete.
// Use this when you need to ensure the new patterns are active before proceeding.
func (bm *BufferedMatcher) UpdatePatternsSync(patterns []Pattern) error {
	bm.patternsMu.Lock()
	bm.patterns = make([]Pattern, len(patterns))
	copy(bm.patterns, patterns)
	bm.patternsMu.Unlock()

	return bm.rebuildAutomaton()
}

// rebuildAutomaton builds a new automaton in the background and swaps it in atomically.
func (bm *BufferedMatcher) rebuildAutomaton() error {
	// Ensure only one rebuild at a time
	bm.buildMu.Lock()
	defer bm.buildMu.Unlock()

	bm.building.Store(true)
	defer bm.building.Store(false)

	// Get current patterns
	bm.patternsMu.RLock()
	patterns := make([]Pattern, len(bm.patterns))
	copy(patterns, bm.patterns)
	bm.patternsMu.RUnlock()

	// If no patterns, clear the automaton
	if len(patterns) == 0 {
		bm.automaton.Store(nil)
		logger.Debug("Cleared AC automaton (no patterns)")
		return nil
	}

	// Build new automaton
	startTime := time.Now()
	newAC := &AhoCorasick{}
	if err := newAC.Build(patterns); err != nil {
		logger.Error("Failed to build AC automaton", "error", err, "pattern_count", len(patterns))
		return err
	}
	buildDuration := time.Since(startTime)

	// Atomic swap - readers will see the new automaton immediately
	bm.automaton.Store(newAC)
	bm.lastBuildTime.Store(time.Now())
	bm.lastBuildDuration.Store(buildDuration)

	logger.Info("AC automaton rebuilt",
		"pattern_count", len(patterns),
		"build_duration", buildDuration,
		"state_count", len(newAC.states))

	return nil
}

// Match finds all patterns that match the input.
// This method is lock-free and safe for concurrent use.
// If no automaton is available, falls back to linear scan.
func (bm *BufferedMatcher) Match(input []byte) []MatchResult {
	ac := bm.automaton.Load()
	if ac != nil {
		return ac.Match(input)
	}

	// Linear scan fallback
	return bm.linearScanMatch(input)
}

// MatchBatch matches multiple inputs against the patterns.
// Uses the automaton if available, otherwise falls back to linear scan.
func (bm *BufferedMatcher) MatchBatch(inputs [][]byte) [][]MatchResult {
	ac := bm.automaton.Load()
	if ac != nil {
		return ac.MatchBatch(inputs)
	}

	// Linear scan fallback
	results := make([][]MatchResult, len(inputs))
	for i, input := range inputs {
		results[i] = bm.linearScanMatch(input)
	}
	return results
}

// MatchUsernames matches a list of extracted usernames against the patterns.
// Returns true if any username matches any pattern.
// This is the primary method for SIP user/phone number matching.
func (bm *BufferedMatcher) MatchUsernames(usernames []string) bool {
	ac := bm.automaton.Load()

	for _, username := range usernames {
		if username == "" {
			continue
		}

		inputBytes := []byte(username)

		if ac != nil {
			// Use AC automaton
			if len(ac.Match(inputBytes)) > 0 {
				return true
			}
		} else {
			// Linear scan fallback
			if len(bm.linearScanMatch(inputBytes)) > 0 {
				return true
			}
		}
	}

	return false
}

// linearScanMatch performs a linear scan through all patterns.
// This is the fallback when no automaton is available.
func (bm *BufferedMatcher) linearScanMatch(input []byte) []MatchResult {
	bm.patternsMu.RLock()
	patterns := bm.patterns
	bm.patternsMu.RUnlock()

	if len(patterns) == 0 {
		return nil
	}

	// Convert input to lowercase for case-insensitive matching
	inputLower := bytes.ToLower(input)
	inputStr := string(inputLower)

	var results []MatchResult
	for i, pattern := range patterns {
		patternLower := bytes.ToLower([]byte(pattern.Text))
		patternStr := string(patternLower)

		matched := false
		switch pattern.Type {
		case filtering.PatternTypePrefix:
			matched = len(inputStr) >= len(patternStr) &&
				inputStr[:len(patternStr)] == patternStr
		case filtering.PatternTypeSuffix:
			matched = len(inputStr) >= len(patternStr) &&
				inputStr[len(inputStr)-len(patternStr):] == patternStr
		case filtering.PatternTypeContains:
			matched = bytes.Contains(inputLower, patternLower)
		}

		if matched {
			results = append(results, MatchResult{
				PatternID:    pattern.ID,
				PatternIndex: i,
				Offset:       len(input),
			})
		}
	}

	return results
}

// PatternCount returns the number of patterns currently loaded.
func (bm *BufferedMatcher) PatternCount() int {
	bm.patternsMu.RLock()
	defer bm.patternsMu.RUnlock()
	return len(bm.patterns)
}

// IsBuilding returns true if a rebuild is currently in progress.
func (bm *BufferedMatcher) IsBuilding() bool {
	return bm.building.Load()
}

// HasAutomaton returns true if an automaton is available.
func (bm *BufferedMatcher) HasAutomaton() bool {
	return bm.automaton.Load() != nil
}

// LastBuildTime returns when the automaton was last built.
func (bm *BufferedMatcher) LastBuildTime() time.Time {
	if t := bm.lastBuildTime.Load(); t != nil {
		return t.(time.Time)
	}
	return time.Time{}
}

// LastBuildDuration returns how long the last build took.
func (bm *BufferedMatcher) LastBuildDuration() time.Duration {
	if d := bm.lastBuildDuration.Load(); d != nil {
		return d.(time.Duration)
	}
	return 0
}

// Stats returns statistics about the buffered matcher.
type Stats struct {
	PatternCount      int
	HasAutomaton      bool
	IsBuilding        bool
	LastBuildTime     time.Time
	LastBuildDuration time.Duration
	StateCount        int
}

// GetStats returns current statistics.
func (bm *BufferedMatcher) GetStats() Stats {
	ac := bm.automaton.Load()
	stateCount := 0
	if ac != nil {
		stateCount = len(ac.states)
	}

	return Stats{
		PatternCount:      bm.PatternCount(),
		HasAutomaton:      ac != nil,
		IsBuilding:        bm.IsBuilding(),
		LastBuildTime:     bm.LastBuildTime(),
		LastBuildDuration: bm.LastBuildDuration(),
		StateCount:        stateCount,
	}
}
