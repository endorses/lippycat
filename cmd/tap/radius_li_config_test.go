//go:build (tap || all) && li

package tap

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/radiusconfig"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestRADIUSLIConfigBridge(t *testing.T) {
	cmd := &cobra.Command{}
	radiusconfig.RegisterLIFlags(cmd)
	require.NoError(t, cmd.ParseFlags([]string{"--li-radius-operator-scope", "operator-a", "--li-radius-profile-revision", "v1", "--li-radius-origin-node", "poi-a", "--li-radius-source", "eth0", "--li-radius-correlation-state-file", "/tmp/poi-a"}))
	var config processor.Config
	require.NoError(t, applyRADIUSLIConfig(cmd, &config))
	require.Equal(t, radius.ScopeBinding{OperatorScope: "operator-a", ProfileRevision: "v1", OriginNodeID: "poi-a", SourceID: "eth0"}, config.LIRADIUSScope)
	require.Equal(t, "/tmp/poi-a", config.LIRADIUSCorrelationStateFile)
}
func TestRADIUSTapRejectsScopeMismatchBeforeConstruction(t *testing.T) {
	for _, tc := range []struct{ name, operator, revision, origin, source, state, want string }{
		{name: "missing-domain", want: "explicit LI operator"},
		{name: "domain", operator: "other", revision: "v1", want: "must agree"},
		{name: "revision", operator: "operator-a", revision: "other", want: "must agree"},
		{name: "origin", operator: "operator-a", revision: "v1", origin: "other-poi", want: "origin node"},
		{name: "interface", operator: "operator-a", revision: "v1", source: "eth99", want: "configured tap interface"},
		{name: "state", operator: "operator-a", revision: "v1", origin: "poi-a-local", source: "eth0", want: "durable correlation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range map[string]string{"operator-scope": tc.operator, "profile-revision": tc.revision, "origin-node": tc.origin, "source": tc.source, "correlation-state-file": tc.state} {
				flag := TapCmd.PersistentFlags().Lookup("li-radius-" + name)
				old, changed := flag.Value.String(), flag.Changed
				require.NoError(t, flag.Value.Set(value))
				flag.Changed = true
				t.Cleanup(func() { require.NoError(t, flag.Value.Set(old)); flag.Changed = changed })
			}
			_, err := newTapRuntime(processor.Config{LIEnabled: true, ProcessorID: "poi-a"}, "udp", protocolcatalog.MustLookup("radius"), tapRuntimeHooks{ConfigureSourceConfig: func(c *source.LocalSourceConfig) {
				c.Interfaces = []string{"eth0"}
				c.RADIUSScope = radius.CaptureScope{OperatorScope: "operator-a", ProfileRevision: "v1"}
			}})
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestRADIUSTapRejectsCorrelationTimeoutMismatch(t *testing.T) {
	_, err := newTapRuntime(processor.Config{LIEnabled: true}, "udp", protocolcatalog.MustLookup("radius"), tapRuntimeHooks{ConfigureSourceConfig: func(c *source.LocalSourceConfig) { c.RADIUSCorrelation.Lifetime = 45 * time.Second }})
	require.ErrorContains(t, err, "transaction timeouts must agree")
}

func TestRADIUSTapAcceptsMatchingCorrelationTimeout(t *testing.T) {
	flag := TapCmd.PersistentFlags().Lookup("li-radius-transaction-timeout")
	old, changed := flag.Value.String(), flag.Changed
	require.NoError(t, flag.Value.Set("45s"))
	flag.Changed = true
	t.Cleanup(func() { require.NoError(t, flag.Value.Set(old)); flag.Changed = changed })
	_, err := newTapRuntime(processor.Config{LIEnabled: true}, "udp", protocolcatalog.MustLookup("radius"), tapRuntimeHooks{ConfigureSourceConfig: func(c *source.LocalSourceConfig) { c.RADIUSCorrelation.Lifetime = 45 * time.Second }})
	require.ErrorContains(t, err, "explicit LI operator")
}
