package mediaadmission

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestShadowDecisionUsesHistoricalEvidence(t *testing.T) {
	window := ShadowWindow{IdentityVerified: true, SelectedNS: 20, PublishedNS: 30, RetiredNS: 50, PublishedGeneration: 3}
	for _, tc := range []struct {
		at, gen uint64
		want    ShadowClassification
	}{{10, 2, ShadowPreselection}, {25, 2, ShadowPublicationWindow}, {31, 2, ShadowPublicationWindow}, {31, 3, ShadowUnexpectedRejection}, {50, 3, ShadowUnclassified}} {
		require.Equal(t, tc.want, ClassifyShadow(ShadowSample{EventMonotonicNS: tc.at, Generation: tc.gen}, window))
	}
	window.IdentityVerified = false
	require.Equal(t, ShadowUnclassified, ClassifyShadow(ShadowSample{EventMonotonicNS: 31, Generation: 3}, window))
}
