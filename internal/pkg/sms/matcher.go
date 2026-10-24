package sms

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/filtering"
)

// Matcher performs case-insensitive literal substring matching with OR semantics.
// It is immutable after construction and safe for concurrent calls.
type Matcher struct{ matcher *ahocorasick.AhoCorasick }

// NewMatcher normalizes keywords; blank keywords disable filtering. Display text
// is never changed. Case normalization is Unicode lowercasing without accent
// folding, stemming, regular expressions, or whitespace rewriting inside text.
func NewMatcher(keywords []string) (*Matcher, error) {
	patterns := make([]ahocorasick.Pattern, 0, len(keywords))
	seen := make(map[string]bool)
	for _, kw := range keywords {
		if !utf8.ValidString(kw) {
			return nil, fmt.Errorf("SMS keyword is not valid UTF-8")
		}
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw == "" || seen[kw] {
			continue
		}
		seen[kw] = true
		patterns = append(patterns, ahocorasick.Pattern{ID: len(patterns), Text: kw, Type: filtering.PatternTypeContains})
	}
	m := &Matcher{}
	if len(patterns) == 0 {
		return m, nil
	}
	var err error
	m.matcher, err = ahocorasick.NewBuilder().Build(patterns)
	if err != nil {
		return nil, fmt.Errorf("build SMS keyword matcher: %w", err)
	}
	return m, nil
}

// Enabled reports whether any nonempty pattern is configured.
func (m *Matcher) Enabled() bool { return m != nil && m.matcher != nil }

// MatchText evaluates literal text. Disabled matching is pass-through.
func (m *Matcher) MatchText(text string) bool {
	return !m.Enabled() || len(m.matcher.Match([]byte(strings.ToLower(text)))) > 0
}

// Match admits only decoded complete text when enabled. A partial segment cannot
// pass even if its preview contains a keyword. Control/report messages require
// transaction association in the adapter, never an independent text match.
func (m *Matcher) Match(message *Message) bool {
	if !m.Enabled() {
		return true
	}
	if message == nil || message.Status != StatusDecoded {
		return false
	}
	if message.Assembly.Status == AssemblyConflict || message.Assembly.Status == AssemblyExpired || message.Assembly.Status == AssemblyResourceLimited {
		return false
	}
	if message.Concat != nil {
		return message.Assembly.Status == AssemblyComplete && m.MatchText(message.Assembly.Text)
	}
	return m.MatchText(message.Text)
}

// LoadKeywordsFromFile reads one literal keyword per line, ignoring blank lines
// and comment lines beginning with '#'. Sources may be concatenated before NewMatcher.
func LoadKeywordsFromFile(filename string) ([]string, error) {
	patterns, err := filtering.LoadPatternsFromFile(filename)
	if err != nil {
		return nil, fmt.Errorf("load SMS keywords: %w", err)
	}
	return patterns, nil
}
