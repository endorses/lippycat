package eventquery

import (
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/testutil/sshfixture"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSSHQueriesUseCanonicalDirectionalEvidenceAndAvailability(t *testing.T) {
	e := sshfixture.Event()
	for _, text := range []string{"kind:ssh", "role:client AND status:complete", "role_evidence:tcp_syn", "hassh:cafb69eb1dbb2a4a505b5b25342a4940", "kex_algorithms:ext-info-c", "encryption_server_client:aes256-ctr", "hassh_version:1.0", "software_version:OpenSSH_9.9", "id.orig_p:40022", "event_id:" + e.Envelope().EventID} {
		query, err := Compile(text)
		require.NoError(t, err, text)
		require.True(t, query(e), text)
	}
	p := Project(e)
	require.Equal(t, []any{e.KEXAlgorithms}, p.Fields["kex_algorithms"].Values)
	partial := events.NewSSHEvent(e.Envelope())
	partial.Status, partial.Reason = events.SSHStatusPartial, events.SSHReasonMissingBanner
	p = Project(partial)
	_, present := p.Fields["hassh"]
	require.False(t, present)
	query, err := Compile("hassh:cafb69eb1dbb2a4a505b5b25342a4940")
	require.NoError(t, err)
	require.False(t, query(partial))
	require.Contains(t, Summary(partial), "partial")
}
