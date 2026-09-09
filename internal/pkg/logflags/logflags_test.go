package logflags

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBindSelectsActiveTopology(t *testing.T) {
	var sniff, tap Values
	sniffFlags := pflag.NewFlagSet("sniff", pflag.ContinueOnError)
	tapFlags := pflag.NewFlagSet("tap", pflag.ContinueOnError)
	Register(sniffFlags, &sniff, false)
	Register(tapFlags, &tap, true)
	require.NoError(t, sniffFlags.Parse([]string{"--log-dir", "/tmp/sniff-logs", "--log-format", "json", "--log-streams", "radius"}))
	Bind(sniffFlags)
	require.Equal(t, "/tmp/sniff-logs", viper.GetString("logs.dir"))
	require.Equal(t, "json", viper.GetString("logs.format"))
	require.Equal(t, []string{"radius"}, viper.GetStringSlice("logs.streams"))
	require.NoError(t, tapFlags.Parse([]string{"--log-dir", "/tmp/tap-logs", "--log-emit-stage", "all"}))
	Bind(tapFlags)
	require.Equal(t, "/tmp/tap-logs", viper.GetString("logs.dir"))
	require.Equal(t, "all", viper.GetString("logs.emit_stage"))
}
