//go:build hunter || tap || all

package hunter

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

func TestAdmissionObserverUsesAuthoritativeNoFilterPolicy(t *testing.T) {
	filter, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	defer filter.Close()
	var prefixes []netip.Prefix
	var noFilters bool
	calls := 0
	require.NoError(t, filter.SetAdmissionObserver(func(p []netip.Prefix, n bool) error {
		// Querying while publishing must not deadlock the application-filter lock.
		_ = filter.GetNoFilterPolicy()
		prefixes = p
		noFilters = n
		calls++
		return nil
	}))
	require.True(t, noFilters)
	require.Equal(t, 1, calls)
	filter.UpdateFilters([]*management.Filter{{Id: "identity", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice"}})
	require.False(t, noFilters, "absence of IP selectors is not absence of all filters")
	require.Empty(t, prefixes)
	filter.UpdateFilters([]*management.Filter{{Id: "ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.9/24"}})
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, prefixes)
	filter.SetNoFilterPolicy(NoFilterPolicyDeny)
	filter.UpdateFilters(nil)
	require.False(t, noFilters)
	filter.SetNoFilterPolicy(NoFilterPolicyAllow)
	require.True(t, noFilters)
}
