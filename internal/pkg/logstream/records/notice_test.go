package records

import (
	"context"
	"encoding/json"
	"github.com/endorses/lippycat/internal/pkg/events"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/logschema"
	"github.com/endorses/lippycat/internal/pkg/logstream"
	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

func TestNoticeRecordRetainsTypedEvidenceAndRedactionAvailability(t *testing.T) {
	e := noticefixture.Event()
	for _, redacted := range []bool{false, true} {
		if redacted {
			e.EvidenceRedacted, e.Evidence, e.DNS.SourceIPs = true, nil, nil
		}
		record, include, err := Notice(e)
		require.NoError(t, err)
		require.True(t, include)
		schema, ok := logschema.ByName("notice")
		require.True(t, ok)
		require.Len(t, record.Values, len(schema.Fields))
		fields := make(map[string]any)
		for i, f := range schema.Fields {
			fields[f.Name] = record.Values[i]
		}
		require.Equal(t, e.Envelope().EventID, fields["event_id"])
		require.Equal(t, "processor", fields["detector_node_id"])
		require.Equal(t, "origin-hunter", fields["node_id"])
		require.Equal(t, 0.93, fields["score"])
		require.Equal(t, redacted, fields["evidence_redacted"])
		require.Equal(t, false, fields["source_ips_truncated"])
		if redacted {
			require.Equal(t, logstream.Unset, fields["source_ips"])
			require.Equal(t, logstream.Unset, fields["evidence_uids"])
		}
	}
}

func TestNoticeTSVAndJSONWritersPreserveEvidenceAndUnsetRedaction(t *testing.T) {
	for _, format := range []logstream.Format{logstream.FormatTSV, logstream.FormatJSON} {
		t.Run(string(format), func(t *testing.T) {
			dir := t.TempDir()
			sink, err := logstream.New(logstream.Config{Directory: dir, Format: format, QueueSize: 4})
			require.NoError(t, err)
			require.NoError(t, sink.Register(events.KindNotice, "notice", Notice))
			require.NoError(t, sink.Start(context.Background()))
			event := noticefixture.Event()
			require.NoError(t, sink.HandleEvent(context.Background(), event))
			event.EvidenceRedacted, event.Evidence, event.DNS.SourceIPs = true, nil, nil
			require.NoError(t, sink.HandleEvent(context.Background(), event))
			require.NoError(t, sink.Close(context.Background()))
			require.Equal(t, uint64(2), sink.Stats().Written)
			contents, err := os.ReadFile(filepath.Join(dir, "notice.log"))
			require.NoError(t, err)
			var rows []string
			for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
				if !strings.HasPrefix(line, "#") {
					rows = append(rows, line)
				}
			}
			require.Len(t, rows, 2)
			if format == logstream.FormatJSON {
				var first, redacted map[string]any
				require.NoError(t, json.Unmarshal([]byte(rows[0]), &first))
				require.NoError(t, json.Unmarshal([]byte(rows[1]), &redacted))
				require.Equal(t, []any{98.0, 100.0}, first["evidence_timestamps"])
				require.Equal(t, []any{"192.0.2.1", "198.51.100.2"}, first["source_ips"])
				require.Equal(t, event.Envelope().EventID, first["event_id"])
				require.Nil(t, redacted["source_ips"])
				require.Nil(t, redacted["evidence_uids"])
				require.Equal(t, true, redacted["evidence_redacted"])
				require.Equal(t, false, redacted["source_ips_truncated"])
			} else {
				schema, _ := logschema.ByName("notice")
				for _, line := range rows {
					require.Len(t, strings.Split(line, "\t"), len(schema.Fields))
				}
				require.Contains(t, rows[0], "98.000000,100.000000")
				require.Contains(t, rows[0], "192.0.2.1,198.51.100.2")
				require.Contains(t, rows[0], event.Envelope().EventID)
				require.NotContains(t, rows[1], "Cfirst")
			}
		})
	}
}
