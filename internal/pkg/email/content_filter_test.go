package email

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContentFilter_NoFilters(t *testing.T) {
	// No filters = pass everything
	filter := NewContentFilter(ContentFilterConfig{})

	assert.False(t, filter.HasFilters())
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@example.com",
		RcptTo:   []string{"recipient@test.com"},
		Subject:  "Test Subject",
	}))
}

func TestContentFilter_SenderPatterns(t *testing.T) {
	filter := NewContentFilter(ContentFilterConfig{
		SenderPatterns: []string{"*@example.com"},
	})

	require.True(t, filter.HasFilters())

	// Should match
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@example.com",
	}))
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "admin@example.com",
	}))

	// Should not match
	assert.False(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@other.com",
	}))
	assert.False(t, filter.Match(&types.EmailMetadata{
		MailFrom: "", // Empty sender
	}))
}

func TestContentFilter_RecipientPatterns(t *testing.T) {
	filter := NewContentFilter(ContentFilterConfig{
		RecipientPatterns: []string{"admin@*"},
	})

	require.True(t, filter.HasFilters())

	// Should match - admin in recipients
	assert.True(t, filter.Match(&types.EmailMetadata{
		RcptTo: []string{"admin@example.com"},
	}))
	assert.True(t, filter.Match(&types.EmailMetadata{
		RcptTo: []string{"user@test.com", "admin@other.com"},
	}))

	// Should not match
	assert.False(t, filter.Match(&types.EmailMetadata{
		RcptTo: []string{"user@example.com"},
	}))
	assert.False(t, filter.Match(&types.EmailMetadata{
		RcptTo: []string{}, // No recipients
	}))
}

func TestContentFilter_AddressPatterns(t *testing.T) {
	// Address patterns match either sender OR recipient
	filter := NewContentFilter(ContentFilterConfig{
		AddressPatterns: []string{"*@suspicious.com"},
	})

	require.True(t, filter.HasFilters())

	// Should match - sender matches
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@suspicious.com",
		RcptTo:   []string{"user@normal.com"},
	}))

	// Should match - recipient matches
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@normal.com",
		RcptTo:   []string{"user@suspicious.com"},
	}))

	// Should not match - neither matches
	assert.False(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@normal.com",
		RcptTo:   []string{"user@other.com"},
	}))
}

func TestContentFilter_SubjectPatterns(t *testing.T) {
	filter := NewContentFilter(ContentFilterConfig{
		SubjectPatterns: []string{"*invoice*"},
	})

	require.True(t, filter.HasFilters())

	// Should match
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject: "Please review this invoice",
	}))
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject: "Invoice #12345",
	}))

	// Should not match
	assert.False(t, filter.Match(&types.EmailMetadata{
		Subject: "Hello World",
	}))
	assert.False(t, filter.Match(&types.EmailMetadata{
		Subject: "", // Empty subject
	}))
}

func TestContentFilter_Keywords(t *testing.T) {
	filter := NewContentFilter(ContentFilterConfig{
		Keywords: []string{"confidential", "urgent"},
	})

	require.True(t, filter.HasFilters())

	// Should match
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject: "This is CONFIDENTIAL information",
	}))
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject: "URGENT: Please respond",
	}))

	// Should not match
	assert.False(t, filter.Match(&types.EmailMetadata{
		Subject: "Hello World",
	}))
	assert.False(t, filter.Match(&types.EmailMetadata{
		Subject: "", // Empty subject
	}))
}

func TestContentFilter_CombinedFilters(t *testing.T) {
	// Combined filters use AND logic between groups
	filter := NewContentFilter(ContentFilterConfig{
		SenderPatterns:  []string{"*@example.com"},
		SubjectPatterns: []string{"*invoice*"},
	})

	require.True(t, filter.HasFilters())

	// Should match - both conditions met
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@example.com",
		Subject:  "Your invoice is ready",
	}))

	// Should not match - only sender matches
	assert.False(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@example.com",
		Subject:  "Hello World",
	}))

	// Should not match - only subject matches
	assert.False(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@other.com",
		Subject:  "Your invoice is ready",
	}))
}

func TestContentFilter_MultiplePatterns(t *testing.T) {
	// Multiple patterns in a group use OR logic
	filter := NewContentFilter(ContentFilterConfig{
		SenderPatterns: []string{"*@example.com", "*@test.com"},
	})

	require.True(t, filter.HasFilters())

	// Should match - first pattern matches
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@example.com",
	}))

	// Should match - second pattern matches
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@test.com",
	}))

	// Should not match
	assert.False(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@other.com",
	}))
}

func TestContentFilter_CaseInsensitive(t *testing.T) {
	filter := NewContentFilter(ContentFilterConfig{
		SenderPatterns: []string{"*@EXAMPLE.COM"},
	})

	// Glob matching is case-insensitive
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "user@example.com",
	}))
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom: "USER@EXAMPLE.COM",
	}))
}

func TestContentFilter_KeywordsInBody(t *testing.T) {
	filter := NewContentFilter(ContentFilterConfig{
		Keywords: []string{"confidential", "secret"},
	})

	require.True(t, filter.HasFilters())

	// Should match - keyword in body only
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject:     "Regular meeting notes",
		BodyPreview: "This document contains confidential information.",
	}))

	// Should match - keyword in body (case insensitive)
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject:     "Hello",
		BodyPreview: "This is TOP SECRET data.",
	}))

	// Should not match - no keyword in subject or body
	assert.False(t, filter.Match(&types.EmailMetadata{
		Subject:     "Hello World",
		BodyPreview: "Just a regular message.",
	}))

	// Should not match - empty body and no keyword in subject
	assert.False(t, filter.Match(&types.EmailMetadata{
		Subject:     "Hello World",
		BodyPreview: "",
	}))
}

func TestContentFilter_KeywordsInSubjectOrBody(t *testing.T) {
	filter := NewContentFilter(ContentFilterConfig{
		Keywords: []string{"urgent"},
	})

	require.True(t, filter.HasFilters())

	// Should match - keyword in subject (body not checked since subject matches)
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject:     "URGENT: Please respond",
		BodyPreview: "Regular body content",
	}))

	// Should match - keyword in body (subject doesn't match)
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject:     "Regular subject",
		BodyPreview: "This is urgent - please review immediately.",
	}))

	// Should match - keyword in both
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject:     "URGENT request",
		BodyPreview: "This is urgent.",
	}))
}

func TestContentFilter_KeywordsWithEmptySubject(t *testing.T) {
	filter := NewContentFilter(ContentFilterConfig{
		Keywords: []string{"important"},
	})

	require.True(t, filter.HasFilters())

	// Should match - keyword in body when subject is empty
	assert.True(t, filter.Match(&types.EmailMetadata{
		Subject:     "",
		BodyPreview: "This is an important message.",
	}))

	// Should not match - neither subject nor body has keyword
	assert.False(t, filter.Match(&types.EmailMetadata{
		Subject:     "",
		BodyPreview: "Just a regular message.",
	}))

	// Should not match - both empty
	assert.False(t, filter.Match(&types.EmailMetadata{
		Subject:     "",
		BodyPreview: "",
	}))
}

func TestContentFilter_CombinedWithBody(t *testing.T) {
	// Test combined filters with body keyword matching
	filter := NewContentFilter(ContentFilterConfig{
		SenderPatterns: []string{"*@example.com"},
		Keywords:       []string{"confidential"},
	})

	require.True(t, filter.HasFilters())

	// Should match - sender matches AND keyword in body
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom:    "user@example.com",
		Subject:     "Regular subject",
		BodyPreview: "This is confidential.",
	}))

	// Should match - sender matches AND keyword in subject
	assert.True(t, filter.Match(&types.EmailMetadata{
		MailFrom:    "user@example.com",
		Subject:     "Confidential report",
		BodyPreview: "",
	}))

	// Should not match - sender matches but no keyword
	assert.False(t, filter.Match(&types.EmailMetadata{
		MailFrom:    "user@example.com",
		Subject:     "Hello",
		BodyPreview: "Regular message.",
	}))

	// Should not match - keyword matches but sender doesn't
	assert.False(t, filter.Match(&types.EmailMetadata{
		MailFrom:    "user@other.com",
		Subject:     "Confidential",
		BodyPreview: "",
	}))
}
