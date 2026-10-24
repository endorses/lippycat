package sms

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMatcherOptionalAndLiteral(t *testing.T) {
	for _, keywords := range [][]string{nil, {"", "  "}} {
		m, e := NewMatcher(keywords)
		if e != nil || m.Enabled() || !m.Match(nil) {
			t.Fatalf("disabled %v", e)
		}
	}
	m, e := NewMatcher([]string{" HELLO ", "ΩΜ", "a.b", "hello"})
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"says HeLLo!", "ωμ", "a.b"} {
		if !m.MatchText(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"bye", "axb", "ω μ"} {
		if m.MatchText(s) {
			t.Fatal(s)
		}
	}
	for _, status := range []DecodeStatus{StatusMalformed, StatusIncomplete, StatusUnsupported, StatusControl} {
		if m.Match(&Message{Status: status, Text: "hello"}) {
			t.Fatal(status)
		}
	}
	if _, e = NewMatcher([]string{string([]byte{255})}); e == nil {
		t.Fatal("invalid keyword accepted")
	}
	a := NewAssembler(Config{})
	pending := a.Add("scope", segment(1, "hel"), time.Unix(100, 0))
	if m.Match(pending) {
		t.Fatal("partial admitted")
	}
	full := a.Add("scope", segment(2, "lo"), time.Unix(100, 0))
	if !m.Match(full) {
		t.Fatal("cross-segment match missed")
	}
}

func TestKeywordFileSources(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keywords")
	if e := os.WriteFile(p, []byte("# comment\n\n  hello \nΩΜ\n"), 0600); e != nil {
		t.Fatal(e)
	}
	k, e := LoadKeywordsFromFile(p)
	if e != nil {
		t.Fatal(e)
	}
	m, e := NewMatcher(append([]string{"bye"}, k...))
	if e != nil || !m.MatchText("HELLO") || !m.MatchText("BYE") || !m.MatchText("ωμ") {
		t.Fatalf("sources %v", e)
	}
	if _, e = LoadKeywordsFromFile(p + "missing"); e == nil {
		t.Fatal("missing file accepted")
	}
}
