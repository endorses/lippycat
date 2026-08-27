//go:build hunter || tap || all

package filter

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestTLSMatcherMatchesStandardJA4Fingerprint(t *testing.T) {
	const fingerprint = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	matcher := NewTLSMatcher()
	matcher.UpdateFilters([]*management.Filter{{
		Id:      "standard-ja4",
		Type:    management.FilterType_FILTER_TLS_JA4,
		Pattern: fingerprint,
		Enabled: true,
	}})

	matched, filterID := matcher.MatchJA4(fingerprint)
	assert.True(t, matched)
	assert.Equal(t, "standard-ja4", filterID)
}
