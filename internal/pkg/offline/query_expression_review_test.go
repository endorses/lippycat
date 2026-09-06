package offline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Exercise storage dependency selection against the full finalized projection,
// including presence accessors whose names also look like ordinary columns.
func TestCompactExpressionSelectedColumnsReview(t *testing.T) {
	d := compactQueryFixture(t, 8)
	fields := []string{"src", "srcip", "dst", "dstip", "srcport", "dstport", "protocol", "info", "node", "nodeid", "interface", "length", "len", "sip.user", "sip.from", "sip.to", "sip.callid", "sip.method", "sip.codec", "sip.fromtag", "sip.totag", "sip.imsi", "sip.imei", "sip.status", "rtp.seq", "rtp.sequence", "rtp.ssrc", "dns.query", "dns.name", "dns.type", "dns.ttl", "dns.latency", "tls.sni", "tls.ja3", "http.host", "http.path", "http.method", "http.status", "http.contentlength", "voip", "sip", "rtp", "dns", "tls", "http", "email", "unknown"}
	for _, field := range fields {
		for _, op := range []string{"has", "equal", "numeric"} {
			e, err := NewExpression(ExpressionSpec{Op: op, Fields: []string{field}, Comparison: "=", Text: "", Number: 0})
			require.NoError(t, err)
			expected := newStatisticsAccumulator()
			var ids []PacketID
			for id := PacketID(0); uint64(id) < d.count; id++ {
				s, held, err := d.readSummary(context.Background(), id)
				require.NoError(t, err)
				if e.Match(s) {
					ids = append(ids, id)
					expected.Add(s)
				}
				d.storage.releaseMemory(held)
			}
			q, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 17, Query: 3}, Expression: e})
			require.NoError(t, err, "%s %s", op, field)
			require.EqualValues(t, len(ids), q.Count(), "%s %s", op, field)
			require.Equal(t, expected.Snapshot(), q.Statistics(), "%s %s", op, field)
			if len(ids) > 0 {
				p, err := q.Page(context.Background(), PageRequest{Token: q.Token(), Limit: 8, MaxBytes: 1 << 20})
				require.NoError(t, err)
				for i, row := range p.Rows {
					require.Equal(t, ids[i], row.ID)
				}
				p.Close()
			}
			require.NoError(t, q.Close())
		}
	}
}
