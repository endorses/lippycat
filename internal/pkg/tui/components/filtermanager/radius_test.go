//go:build tui || all

package filtermanager

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRADIUSCapabilityAndDisplay(t *testing.T) {
	typ := management.FilterType_FILTER_RADIUS_USERNAME
	require.Equal(t, "RADIUS User", AbbreviateType(typ))
	require.Equal(t, "radius", GetRequiredProtocolMode(typ))
	legacy := HunterSelectorItem{HunterID: "legacy"}
	require.False(t, HunterSupportsFilterType(legacy, typ))
	claimed := HunterSelectorItem{HunterID: "claimed", Capabilities: &management.HunterCapabilities{FilterTypes: []string{"radius_username"}}}
	require.False(t, HunterSupportsFilterType(claimed, typ))
	claimed.Capabilities.RadiusFilterVersion = 1
	require.True(t, HunterSupportsFilterType(claimed, typ))
	require.False(t, HunterSupportsFilterType(claimed, management.FilterType_FILTER_RADIUS_COMPOUND))
	require.Equal(t, []HunterSelectorItem{claimed}, FilterHuntersByCapability([]HunterSelectorItem{legacy, claimed}, typ))
}
