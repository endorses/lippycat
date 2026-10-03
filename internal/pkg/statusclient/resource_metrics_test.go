package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestResourceMetricsJSONCompatibility(t *testing.T) {
	for _, capacity := range []float64{0, 1.5} {
		stats := &management.HunterStats{CpuPercent: 120, CpuCapacityCores: capacity}
		if capacity != 0 {
			stats.MetricsSampleTimeNs = 123
		}
		got := hunterToJSON(&management.ConnectedHunter{Stats: stats})
		wire, err := json.Marshal(got.Stats)
		require.NoError(t, err)
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(wire, &fields))
		require.JSONEq(t, `120`, string(fields["cpu_percent"]))
		if capacity == 0 {
			require.NotContains(t, fields, "cpu_capacity_cores")
			require.NotContains(t, fields, "metrics_sample_time_ns")
		} else {
			require.JSONEq(t, `1.5`, string(fields["cpu_capacity_cores"]))
			require.JSONEq(t, `123`, string(fields["metrics_sample_time_ns"]))
		}
	}
}
