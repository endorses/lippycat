//go:build (processor || all) && li

package process

import (
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLIStoreKeysReachProcessorConfig(t *testing.T) {
	command := ProcessCmd
	flags := command.Flags()
	for _, name := range []string{"li-state-file", "li-state-key-file", "li-state-key-id", "li-state-read-key", "li-delivery-x2-spool-key-file", "li-delivery-x2-spool-key-id", "li-delivery-x2-spool-legacy-key-id", "li-delivery-x2-spool-read-key", "li-delivery-x3-spool-dir", "li-delivery-x3-spool-max-bytes", "li-delivery-x3-max-age", "li-delivery-x3-spool-key-file", "li-delivery-x3-spool-key-id", "li-delivery-x3-spool-read-key", "li-delivery-x3-spool-replay-policy", "li-delivery-x3-spool-replay-manifest", "li-delivery-x3-spool-export-manifest"} {
		flag := flags.Lookup(name)
		require.NotNil(t, flag)
		changed := flag.Changed
		if values, ok := flag.Value.(pflag.SliceValue); ok {
			before := values.GetSlice()
			t.Cleanup(func() { require.NoError(t, values.Replace(before)); flag.Changed = changed })
		} else {
			before := flag.Value.String()
			t.Cleanup(func() { require.NoError(t, flag.Value.Set(before)); flag.Changed = changed })
		}
	}
	require.NoError(t, command.ParseFlags([]string{
		"--li-state-file=/explicit/state.enc", "--li-state-key-file=/keys/state", "--li-state-key-id=state-v2", "--li-state-read-key=state-v1=/keys/state-old",
		"--li-delivery-x2-spool-key-file=/keys/x2", "--li-delivery-x2-spool-key-id=x2-v2", "--li-delivery-x2-spool-legacy-key-id=x2-v1", "--li-delivery-x2-spool-read-key=x2-v1=/keys/x2-old",
		"--li-delivery-x3-spool-replay-policy=purge", "--li-delivery-x3-spool-dir=/explicit/x3", "--li-delivery-x3-spool-max-bytes=134217728", "--li-delivery-x3-max-age=60s", "--li-delivery-x3-spool-key-file=/keys/x3", "--li-delivery-x3-spool-key-id=x3-v2", "--li-delivery-x3-spool-read-key=x3-v1=/keys/x3-old",
	}))
	var config processor.Config
	require.NoError(t, applyLIStoreKeyConfig(command, &config))
	require.Equal(t, "/explicit/state.enc", config.LIStateFile)
	require.Equal(t, securestore.KeyRef{ID: "state-v2", File: "/keys/state"}, config.LIStateKeys.Active)
	require.Equal(t, []securestore.KeyRef{{ID: "state-v1", File: "/keys/state-old"}}, config.LIStateKeys.Prior)
	require.Equal(t, "x2-v2", config.LIDeliveryX2SpoolKeyID)
	require.Equal(t, "x2-v1", config.LIDeliveryX2SpoolLegacyKeyID)
	require.Equal(t, []securestore.KeyRef{{ID: "x2-v1", File: "/keys/x2-old"}}, config.LIDeliveryX2SpoolReadKeys)
	require.Equal(t, "purge", config.LIDeliveryX3SpoolReplayPolicy)
	require.Equal(t, "/explicit/x3", config.LIDeliveryX3SpoolDir)
	require.EqualValues(t, 128<<20, config.LIDeliveryX3SpoolMaxBytes)
	require.Equal(t, "x3-v2", config.LIDeliveryX3SpoolKeyID)
	require.Equal(t, "/keys/x3", config.LIDeliveryX3SpoolKeyFile)
	require.Equal(t, []securestore.KeyRef{{ID: "x3-v1", File: "/keys/x3-old"}}, config.LIDeliveryX3SpoolReadKeys)
}
