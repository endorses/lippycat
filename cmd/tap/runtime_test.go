//go:build tap || all

package tap

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTapSourceConfigUsesProtocolSpec(t *testing.T) {
	oldInterfaces, oldBatchSize, oldBatchTimeout, oldBufferSize := interfaces, batchSize, batchTimeout, bufferSize
	t.Cleanup(func() {
		interfaces, batchSize, batchTimeout, bufferSize = oldInterfaces, oldBatchSize, oldBatchTimeout, oldBufferSize
	})
	interfaces = []string{"eth0", "eth1"}
	batchSize, batchTimeout, bufferSize = 42, 250, 2048

	got := tapSourceConfig(processor.Config{ProcessorID: "tap-test"}, "tcp port 443", ProtocolSpec{Name: "tls"})
	require.Equal(t, []string{"eth0", "eth1"}, got.Interfaces)
	require.Equal(t, "tcp port 443", got.BPFFilter)
	require.Equal(t, 42, got.BatchSize)
	require.Equal(t, 250*time.Millisecond, got.BatchTimeout)
	require.Equal(t, 2048, got.BufferSize)
	require.Equal(t, 1000, got.BatchBuffer)
	require.Equal(t, "tap-test", got.ProcessorID)
	require.Equal(t, "tls", got.ProtocolMode)
}

func TestTapProtocolViperBindingsRetainDefaults(t *testing.T) {
	require.Equal(t, "53", viper.GetString("tap.dns.ports"))
	require.Equal(t, "80,8080,8000,3000,8888", viper.GetString("tap.http.ports"))
	require.Equal(t, "443", viper.GetString("tap.tls.ports"))
	require.Equal(t, "all", viper.GetString("tap.email.protocol"))
}

func TestTapProtocolHelpRetainsExamples(t *testing.T) {
	for _, name := range []string{"dns", "http", "tls", "email", "voip"} {
		t.Run(name, func(t *testing.T) {
			cmd, _, err := TapCmd.Find([]string{name})
			require.NoError(t, err)
			require.Contains(t, cmd.Long, "lc tap "+name)
		})
	}
}

func TestTapProtocolCommandsRetainFlagDefaults(t *testing.T) {
	tests := []struct {
		command string
		flag    string
		value   string
	}{
		{"dns", "dns-port", "53"},
		{"http", "http-port", "80,8080,8000,3000,8888"},
		{"tls", "tls-port", "443"},
		{"email", "protocol", "all"},
		{"voip", "sip-port", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command+"/"+tt.flag, func(t *testing.T) {
			cmd, _, err := TapCmd.Find([]string{tt.command})
			require.NoError(t, err)
			flag := cmd.Flags().Lookup(tt.flag)
			require.NotNil(t, flag)
			require.Equal(t, tt.value, flag.DefValue)
		})
	}
}
