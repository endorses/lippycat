//go:build cli || all

package sniff

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radiusconfig"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestReplayPermissionDenialStopsBeforePacketOutput(t *testing.T) {
	oldRead, oldWrite, oldFormat, oldQuiet := readFile, writeFile, format, quiet
	oldStdout := os.Stdout
	settings := map[string]any{}
	for _, key := range []string{"sniff.virtual_interface", "sniff.replay_loop", "sniff.replay_loop_delay", "logs.dir", "files.extract", "sniff.write_file", "sniff.format", "sniff.quiet"} {
		settings[key] = viper.Get(key)
	}
	t.Cleanup(func() {
		readFile, writeFile, format, quiet = oldRead, oldWrite, oldFormat, oldQuiet
		os.Stdout = oldStdout
		for key, value := range settings {
			viper.Set(key, value)
		}
	})
	readFile, writeFile, format, quiet = "", "", "json", false
	viper.Set("sniff.virtual_interface", true)
	viper.Set("sniff.replay_loop_delay", time.Duration(0))
	viper.Set("logs.dir", "")
	viper.Set("files.extract", false)
	for _, count := range []int{1, 0} {
		for _, mode := range []string{"generic", "radius"} {
			for _, denied := range []error{vinterface.ErrPermissionDenied, vinterface.ErrNetNSPermissionDenied, &os.PathError{Op: "open", Path: "/dev/net/tun", Err: syscall.EACCES}} {
				t.Run(fmt.Sprintf("%s/count%d/%v", mode, count, denied), func(t *testing.T) {
					viper.Set("sniff.replay_loop", count)
					dir := t.TempDir()
					output := filepath.Join(dir, "stdout.jsonl")
					writeFile = filepath.Join(dir, "existing-output.pcap")
					original := []byte("previous capture must remain intact")
					require.NoError(t, os.WriteFile(writeFile, original, 0o600))
					f, err := os.Create(output)
					require.NoError(t, err)
					os.Stdout = f
					defer func() { os.Stdout = oldStdout; require.NoError(t, f.Close()) }()
					var radiusConfig *radiusconfig.Config
					if mode == "radius" {
						radiusConfig = &radiusconfig.Config{}
					}
					starts := 0
					err = sniffConfiguredWithVirtualInterface(&cobra.Command{}, []string{"unopened-input.pcap"}, radiusConfig, "", func(context.Context, vinterface.Config, bool, time.Duration) (*virtualInterfaceEnvelopeSink, error) {
						starts++
						return nil, fmt.Errorf("start virtual interface: %w", denied)
					})
					require.ErrorIs(t, err, denied, "permission denial must return before any input file is opened")
					require.Equal(t, 1, starts)
					data, err := os.ReadFile(output)
					require.NoError(t, err)
					require.Empty(t, data, "replay must emit no packets after permission denial")
					retained, err := os.ReadFile(writeFile)
					require.NoError(t, err)
					require.Equal(t, original, retained)
				})
			}
		}
	}
}
