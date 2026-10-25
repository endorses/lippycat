package records

import (
	"context"
	"encoding/json"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logschema"
	"github.com/endorses/lippycat/internal/pkg/logstream"
	"github.com/endorses/lippycat/internal/testutil/sshfixture"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHCanonicalWritersPreserveOrderedEvidenceAndUnsetPartialFields(t *testing.T) {
	complete := sshfixture.Event()
	partial := events.NewSSHEvent(complete.Envelope())
	partial.Status, partial.Reason = events.SSHStatusPartial, events.SSHReasonGap
	partial.Banner, partial.ProtocolVersion, partial.SoftwareVersion = complete.Banner, complete.ProtocolVersion, complete.SoftwareVersion
	for _, format := range []logstream.Format{logstream.FormatJSON, logstream.FormatTSV} {
		t.Run(string(format), func(t *testing.T) {
			dir := t.TempDir()
			sink, err := logstream.New(logstream.Config{Directory: dir, Format: format, QueueSize: 4})
			require.NoError(t, err)
			require.NoError(t, sink.Register(events.KindSSH, "ssh", SSH))
			require.NoError(t, sink.Start(context.Background()))
			for _, e := range []events.SSHEvent{complete, partial} {
				require.NoError(t, sink.HandleEvent(context.Background(), e))
			}
			require.NoError(t, sink.Close(context.Background()))
			data, err := os.ReadFile(filepath.Join(dir, "ssh.log"))
			require.NoError(t, err)
			var rows []string
			for _, row := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if !strings.HasPrefix(row, "#") {
					rows = append(rows, row)
				}
			}
			require.Len(t, rows, 2)
			schema, _ := logschema.ByName("ssh")
			if format == logstream.FormatJSON {
				var full, p map[string]any
				require.NoError(t, json.Unmarshal([]byte(rows[0]), &full))
				require.NoError(t, json.Unmarshal([]byte(rows[1]), &p))
				require.Equal(t, complete.KEXAlgorithms, full["kex_algorithms"])
				require.Equal(t, complete.EncryptionServerClient, full["encryption_server_client"])
				require.Equal(t, complete.HASSH, full["hassh"])
				require.Equal(t, "", full["languages_client_server"])
				for _, field := range []string{"hassh", "hassh_algorithms", "kex_algorithms", "languages_client_server", "first_kex_packet_follows"} {
					require.Nil(t, p[field], field)
				}
				require.Equal(t, "gap", p["reason"])
				require.Equal(t, complete.Banner, p["banner"])
			} else {
				for _, row := range rows {
					require.Len(t, strings.Split(row, "\t"), len(schema.Fields))
				}
				require.Contains(t, rows[0], complete.KEXAlgorithms)
				require.NotContains(t, rows[1], complete.HASSH)
			}
		})
	}
}
