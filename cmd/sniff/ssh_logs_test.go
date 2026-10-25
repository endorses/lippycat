//go:build cli || all

package sniff

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
)

func TestSSHGenericSniffStructuredLogs(t *testing.T) {
	setSniffAnalysisConfig(t, map[string]any{"logs.streams": []string{"ssh"}, "logs.format": "json", "files.extract": false, "events.ssh.enabled": true})
	dir := t.TempDir()
	s, err := newSniffEventSession(dir, nil, "ssh-test", nil)
	require.NoError(t, err)
	require.NotNil(t, s)
	t.Cleanup(func() { s.analysis.Close(); require.NoError(t, s.dispatcher.Close(context.Background())) })
	packets, err := eventfixture.SSHMessages()
	require.NoError(t, err)
	for i := range packets {
		s.observe(&packets[i])
	}
	s.analysis.EOF()
	s.analysis.Close()
	require.NoError(t, s.dispatcher.Close(context.Background()))
	data, err := os.ReadFile(filepath.Join(dir, "ssh.log"))
	require.NoError(t, err)
	var roles []string
	var uid string
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var row map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &row))
		count++
		if uid == "" {
			uid = row["uid"].(string)
		}
		require.Equal(t, uid, row["uid"])
		require.NotEmpty(t, row["event_id"])
		if row["status"] == "complete" {
			roles = append(roles, row["role"].(string))
			require.NotEmpty(t, row["hassh"])
			require.Equal(t, "1.0", row["hassh_version"])
		} else {
			require.Equal(t, "banner", row["status"])
			require.Nil(t, row["hassh"])
		}
	}
	require.Equal(t, 4, count)
	require.ElementsMatch(t, []string{"client", "server"}, roles)
}
