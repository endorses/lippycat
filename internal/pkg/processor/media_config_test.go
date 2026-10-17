//go:build processor || tap || all

package processor

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/stretchr/testify/require"
)

func TestMediaSourceDomainMappingCannotAliasSeparateNetworks(t *testing.T) {
	for _, mappings := range [][]MediaSourceMapping{
		{{HunterID: "a", Interface: "left", Domain: 1, HunterDomain: 2}, {HunterID: "a", Interface: "right", Domain: 3, HunterDomain: 2}},
		{{HunterID: "*", Interface: "left", Domain: 1, HunterDomain: 2}, {HunterID: "a", Interface: "right", Domain: 3, HunterDomain: 2}},
		{{HunterID: "a", Interface: "left", Domain: 1}, {HunterID: "a", Interface: "left", Domain: 1}},
	} {
		_, err := (MediaRulesConfig{Settings: mediarules.Settings{Enabled: true}, Sources: mappings}).normalize("processor.example.invalid")
		require.Error(t, err)
	}
	_, err := (MediaRulesConfig{Settings: mediarules.Settings{Enabled: true}, Sources: []MediaSourceMapping{{HunterID: "a", Interface: "left", Domain: 1, HunterDomain: 2}, {HunterID: "b", Interface: "left", Domain: 3, HunterDomain: 2}}}).normalize("processor.example.invalid")
	require.NoError(t, err, "separate hunters can use the same local domain number")
}
