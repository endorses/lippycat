//go:build tap || all

package tap

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTapCapturePolicyConfigAndSourceDomains(t *testing.T) {
	oldSignal, oldMedia := viper.Get("tap.voip.signalling_policy"), viper.Get("tap.voip.media_policy")
	t.Cleanup(func() {
		viper.Set("tap.voip.signalling_policy", oldSignal)
		viper.Set("tap.voip.media_policy", oldMedia)
	})
	for _, tt := range []struct {
		signal, media string
		valid         bool
	}{{"", "", true}, {"all", "processor", true}, {"none", "local", true}, {"invalid", "local", false}, {"all", "invalid", false}} {
		viper.Set("tap.voip.signalling_policy", tt.signal)
		viper.Set("tap.voip.media_policy", tt.media)
		_, err := tapCapturePolicies()
		require.Equal(t, tt.valid, err == nil)
	}
	cfg := processor.MediaRulesConfig{Sources: []processor.MediaSourceMapping{{HunterID: "tap-local", Interface: "left", Domain: 4, HunterDomain: 0}, {HunterID: "tap-local", Interface: "right", Domain: 5, HunterDomain: 1}}}
	cfg.ProcessorID = "tap"
	domains, err := tapMediaDomains(cfg, []string{"left,right"}, nil)
	require.NoError(t, err)
	require.Equal(t, map[string]mediaadmission.DomainID{"left": 0, "right": 1}, domains)
	_, err = tapMediaDomains(cfg, []string{"any"}, nil)
	require.Error(t, err)
	_, err = tapMediaDomains(cfg, []string{"right"}, map[string]mediaadmission.DomainID{"right": 2})
	require.Error(t, err)
}
func TestTapProcessorMediaRoutingIsolatesDomainsWithoutKernelAdmission(t *testing.T) {
	pc := voipprocessor.DefaultConfig()
	pc.ApplicationFilter = tapAdmissionFilter{}
	routing, err := newTapVoIPRouting(pc, *voip.DefaultConfig(), 1, nil, 0, []string{"left", "right"}, tapVoIPSourcePolicy{Policies: voip.CapturePolicies{Signalling: voip.SignallingAll, Media: voip.MediaProcessor}, InterfaceDomains: map[string]mediaadmission.DomainID{"right": 1}})
	require.NoError(t, err)
	defer routing.Close()
	require.Len(t, routing.children, 2)
	require.NotSame(t, routing.engines[0], routing.engines[1])
	require.Empty(t, routing.bridges)
}
