//go:build hunter || tap || all

package filter

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestTLSMatcherMatchesJA4(t *testing.T) {
	const fingerprint = "t13d0206h1_62ed6f6ca7ad_fb71836bce29"
	matcher := NewTLSMatcher()
	matcher.UpdateFilters([]*management.Filter{{
		Id:      "ja4-filter",
		Type:    management.FilterType_FILTER_TLS_JA4,
		Pattern: fingerprint,
		Enabled: true,
	}})

	matched, filterID := matcher.MatchJA4(fingerprint)

	assert.True(t, matched)
	assert.Equal(t, "ja4-filter", filterID)
}
