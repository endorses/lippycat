//go:build cli || all

package sniff

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type networkSniffSink struct{ observations []events.Event }

func (s *networkSniffSink) HandleEvent(_ context.Context, e events.Event) error {
	s.observations = append(s.observations, e)
	return nil
}
func (*networkSniffSink) Flush(context.Context) error { return nil }
func (*networkSniffSink) Close(context.Context) error { return nil }
func TestNetworkSniffLogsAndIndependentEvents(t *testing.T) {
	viper.Set("logs.streams", []string{"dhcp", "ntp"})
	viper.Set("logs.format", "json")
	t.Cleanup(func() { viper.Set("logs.streams", nil); viper.Set("logs.format", nil) })
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "logs-disabled", true: "logs-enabled"}[enabled], func(t *testing.T) {
			dir := ""
			if enabled {
				dir = t.TempDir()
			}
			sink := &networkSniffSink{}
			session, err := newSniffEventSession(dir, nil, "network-test", sink)
			require.NoError(t, err)
			packets, err := eventfixture.NetworkMessages()
			require.NoError(t, err)
			for _, info := range packets {
				session.observe(&info)
			}
			session.analysis.EOF()
			session.analysis.Close()
			require.NoError(t, session.dispatcher.Close(context.Background()))
			eventfixture.AssertNetworkMessages(t, sink.observations)
			if enabled {
				for stream, count := range map[string]int{"dhcp": 3, "ntp": 2} {
					content, err := os.ReadFile(filepath.Join(dir, stream+".log"))
					require.NoError(t, err)
					lines := strings.Split(strings.TrimSpace(string(content)), "\n")
					require.Len(t, lines, count, "message records must not coalesce")
					var rows []map[string]any
					for _, line := range lines {
						var row map[string]any
						require.NoError(t, json.Unmarshal([]byte(line), &row))
						rows = append(rows, row)
					}
					if stream == "dhcp" {
						require.Equal(t, float64(0x12345678), rows[0]["transaction_id"])
						require.Equal(t, "00ff01", rows[0]["client_identifier"])
						require.Equal(t, "unique", rows[1]["association"])
					} else {
						require.Equal(t, float64(-20), rows[0]["precision"])
						require.Equal(t, "ee43fc0080000000", rows[0]["transmit_raw"])
						require.Equal(t, "unique", rows[1]["association"])
					}
				}
			}
		})
	}
}

func TestInventorySniffLogsAndIndependentEvents(t *testing.T) {
	for key, value := range map[string]any{"logs.streams": []string{"known_hosts", "known_services"}, "logs.format": "json", "events.inventory.enabled": true, "events.inventory.local_cidrs": []string{"192.0.2.0/24"}} {
		old := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, old) })
	}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "logs-disabled", true: "logs-enabled"}[enabled], func(t *testing.T) {
			dir := ""
			if enabled {
				dir = t.TempDir()
			}
			sink := &networkSniffSink{}
			session, err := newSniffEventSession(dir, nil, "inventory-test", sink)
			require.NoError(t, err)
			packets, err := eventfixture.InventoryMessages()
			require.NoError(t, err)
			for _, info := range packets {
				session.observe(&info)
			}
			session.analysis.EOF()
			session.analysis.Close()
			require.NoError(t, session.dispatcher.Close(context.Background()))
			eventfixture.AssertInventory(t, sink.observations)
			if enabled {
				for stream, count := range map[string]int{"known_hosts": 2, "known_services": 1} {
					content, err := os.ReadFile(filepath.Join(dir, stream+".log"))
					require.NoError(t, err)
					lines := strings.Split(strings.TrimSpace(string(content)), "\n")
					require.Len(t, lines, count)
					for _, line := range lines {
						var row map[string]any
						require.NoError(t, json.Unmarshal([]byte(line), &row))
						require.Contains(t, row, "host")
						require.Equal(t, "192.0.2.20", row["id.orig_h"])
						if stream == "known_services" {
							require.Equal(t, "ntp", row["service"])
							require.Equal(t, "ntp_exchange", row["evidence"])
							require.Equal(t, float64(123), row["port"])
						}
					}
				}
			}
		})
	}
}
