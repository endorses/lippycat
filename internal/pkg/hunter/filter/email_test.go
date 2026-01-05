//go:build hunter || all

package filter

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailMatcher_UpdateFilters(t *testing.T) {
	matcher := NewEmailMatcher()

	// Initially no filters
	assert.False(t, matcher.HasFilters())

	// Add filters
	filters := []*management.Filter{
		{
			Id:      "filter-1",
			Type:    management.FilterType_FILTER_EMAIL_ADDRESS,
			Pattern: "*@example.com",
			Enabled: true,
		},
		{
			Id:      "filter-2",
			Type:    management.FilterType_FILTER_EMAIL_SUBJECT,
			Pattern: "*confidential*",
			Enabled: true,
		},
		{
			Id:      "filter-disabled",
			Type:    management.FilterType_FILTER_EMAIL_ADDRESS,
			Pattern: "*@disabled.com",
			Enabled: false, // Should be ignored
		},
		{
			Id:      "filter-dns",
			Type:    management.FilterType_FILTER_DNS_DOMAIN, // Different type - should be ignored
			Pattern: "*.example.com",
			Enabled: true,
		},
	}

	matcher.UpdateFilters(filters)

	require.True(t, matcher.HasFilters())
}

func TestEmailMatcher_MatchAddress(t *testing.T) {
	matcher := NewEmailMatcher()

	filters := []*management.Filter{
		{
			Id:      "filter-example",
			Type:    management.FilterType_FILTER_EMAIL_ADDRESS,
			Pattern: "*@example.com",
			Enabled: true,
		},
		{
			Id:      "filter-admin",
			Type:    management.FilterType_FILTER_EMAIL_ADDRESS,
			Pattern: "admin@*",
			Enabled: true,
		},
	}

	matcher.UpdateFilters(filters)

	tests := []struct {
		name      string
		address   string
		wantMatch bool
		wantIDs   []string
	}{
		{
			name:      "match suffix pattern",
			address:   "user@example.com",
			wantMatch: true,
			wantIDs:   []string{"filter-example"},
		},
		{
			name:      "match prefix pattern",
			address:   "admin@other.com",
			wantMatch: true,
			wantIDs:   []string{"filter-admin"},
		},
		{
			name:      "match both patterns",
			address:   "admin@example.com",
			wantMatch: true,
			wantIDs:   []string{"filter-example", "filter-admin"},
		},
		{
			name:      "no match",
			address:   "user@other.com",
			wantMatch: false,
			wantIDs:   nil,
		},
		{
			name:      "empty address",
			address:   "",
			wantMatch: false,
			wantIDs:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, filterIDs := matcher.MatchAddress(tt.address)
			assert.Equal(t, tt.wantMatch, matched)
			assert.ElementsMatch(t, tt.wantIDs, filterIDs)
		})
	}
}

func TestEmailMatcher_MatchSubject(t *testing.T) {
	matcher := NewEmailMatcher()

	filters := []*management.Filter{
		{
			Id:      "filter-confidential",
			Type:    management.FilterType_FILTER_EMAIL_SUBJECT,
			Pattern: "*confidential*",
			Enabled: true,
		},
		{
			Id:      "filter-urgent",
			Type:    management.FilterType_FILTER_EMAIL_SUBJECT,
			Pattern: "URGENT*",
			Enabled: true,
		},
	}

	matcher.UpdateFilters(filters)

	tests := []struct {
		name      string
		subject   string
		wantMatch bool
		wantIDs   []string
	}{
		{
			name:      "match contains pattern",
			subject:   "This document is confidential",
			wantMatch: true,
			wantIDs:   []string{"filter-confidential"},
		},
		{
			name:      "match prefix pattern",
			subject:   "URGENT: Please respond",
			wantMatch: true,
			wantIDs:   []string{"filter-urgent"},
		},
		{
			name:      "case insensitive match",
			subject:   "CONFIDENTIAL information",
			wantMatch: true,
			wantIDs:   []string{"filter-confidential"},
		},
		{
			name:      "no match",
			subject:   "Hello World",
			wantMatch: false,
			wantIDs:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, filterIDs := matcher.MatchSubject(tt.subject)
			assert.Equal(t, tt.wantMatch, matched)
			assert.ElementsMatch(t, tt.wantIDs, filterIDs)
		})
	}
}

func TestEmailMatcher_MatchEnvelope(t *testing.T) {
	matcher := NewEmailMatcher()

	filters := []*management.Filter{
		{
			Id:      "filter-sender",
			Type:    management.FilterType_FILTER_EMAIL_ADDRESS,
			Pattern: "*@suspicious.com",
			Enabled: true,
		},
		{
			Id:      "filter-subject",
			Type:    management.FilterType_FILTER_EMAIL_SUBJECT,
			Pattern: "*invoice*",
			Enabled: true,
		},
	}

	matcher.UpdateFilters(filters)

	tests := []struct {
		name      string
		sender    string
		recipient string
		subject   string
		wantMatch bool
		wantIDs   []string
	}{
		{
			name:      "match sender only",
			sender:    "attacker@suspicious.com",
			recipient: "victim@safe.com",
			subject:   "Hello",
			wantMatch: true,
			wantIDs:   []string{"filter-sender"},
		},
		{
			name:      "match recipient only",
			sender:    "user@normal.com",
			recipient: "forward@suspicious.com",
			subject:   "Hello",
			wantMatch: true,
			wantIDs:   []string{"filter-sender"},
		},
		{
			name:      "match subject only",
			sender:    "user@normal.com",
			recipient: "other@safe.com",
			subject:   "Your invoice is ready",
			wantMatch: true,
			wantIDs:   []string{"filter-subject"},
		},
		{
			name:      "match multiple",
			sender:    "user@suspicious.com",
			recipient: "other@safe.com",
			subject:   "Invoice attached",
			wantMatch: true,
			wantIDs:   []string{"filter-sender", "filter-subject"},
		},
		{
			name:      "no match",
			sender:    "user@normal.com",
			recipient: "other@safe.com",
			subject:   "Hello World",
			wantMatch: false,
			wantIDs:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, filterIDs := matcher.MatchEnvelope(tt.sender, tt.recipient, tt.subject)
			assert.Equal(t, tt.wantMatch, matched)
			assert.ElementsMatch(t, tt.wantIDs, filterIDs)
		})
	}
}

func TestEmailMatcher_DisabledFilters(t *testing.T) {
	matcher := NewEmailMatcher()

	// Only disabled filters
	filters := []*management.Filter{
		{
			Id:      "filter-1",
			Type:    management.FilterType_FILTER_EMAIL_ADDRESS,
			Pattern: "*@example.com",
			Enabled: false,
		},
	}

	matcher.UpdateFilters(filters)

	assert.False(t, matcher.HasFilters())

	matched, filterIDs := matcher.MatchAddress("user@example.com")
	assert.False(t, matched)
	assert.Empty(t, filterIDs)
}
