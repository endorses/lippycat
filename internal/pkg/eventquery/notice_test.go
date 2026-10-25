package eventquery

import (
	"testing"

	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

func TestNoticeProjectionQueriesPreserveEvidenceAndAuthority(t *testing.T) {
	event := noticefixture.Event()
	for _, query := range []string{"kind:notice", "detector:dns.tunneling AND severity:warning", "domain:example.test", "score:>=0.9", "threshold:0.7", "queries:>=50", "source_ips:198.51.100.2", "evidence_uids:Cfirst", "evidence_timestamps:>=1970-01-01T00:01:38Z", "detector_node_id:processor", "evidence_redacted:false"} {
		predicate, err := Compile(query)
		require.NoError(t, err, query)
		require.True(t, predicate(event), query)
	}
	require.Contains(t, Summary(event), "security example.test score=0.930")
	event.EvidenceRedacted, event.Evidence, event.DNS.SourceIPs = true, nil, nil
	projection := Project(event)
	require.NotContains(t, projection.Fields, "source_ips")
	require.NotContains(t, projection.Fields, "evidence_uids")
	predicate, err := Compile("evidence_redacted:true")
	require.NoError(t, err)
	require.True(t, predicate(event))
}
