//go:build tui || all

package filters

import (
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestOfflineExpressionLimitFallback(t *testing.T) {
	for _, kind := range []string{"depth", "stack", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			chain := NewFilterChain()
			switch kind {
			case "depth":
				f, err := ParseBooleanExpression(strings.Repeat("NOT ", 65)+"impossible", func(s string) Filter {
					return NewTextFilter(s, nil)
				})
				require.NoError(t, err)
				chain.Add(f)
			case "stack":
				for i := 0; i < 257; i++ {
					chain.Add(NewTextFilter("", nil))
				}
			case "bytes":
				chain.Add(NewTextFilter(strings.Repeat("x", 1<<20), nil))
			}
			require.Equal(t, kind != "bytes", chain.Match(types.PacketDisplay{}))
			e, err := chain.OfflineExpression()
			require.NoError(t, err)
			require.Nil(t, e, "storage expression limits must preserve opaque filtering")
		})
	}
}

func TestOfflineExpressionInvalidFilterStillFails(t *testing.T) {
	chain := NewFilterChain()
	chain.Add(&NumericComparisonFilter{field: "length", operator: "!="})
	_, err := chain.OfflineExpression()
	require.ErrorContains(t, err, "invalid numeric comparison")
}

func TestOfflineExpressionParity(t *testing.T) {
	packets := []types.PacketDisplay{
		{},
		{SrcIP: "192.168.1.10", DstIP: "::ffff:192.168.1.2", SrcPort: "05060", DstPort: "80", Protocol: "SIP", Info: "INVITE From: <sip:alice@example.org> To: bob", NodeID: "Local"},
		{SrcIP: "10.1.2.3", DstIP: "192.168.1.1", SrcPort: "5060", DstPort: "0", Protocol: "RTP", NodeID: "edge-a", Length: 100, VoIPData: &types.VoIPMetadata{}},
		{Protocol: "SIP", NodeID: "edge-a-01", VoIPData: &types.VoIPMetadata{User: "Alice", From: "bob", To: "CAROL", FromTag: "abc", ToTag: "def", Method: "INVITE", CallID: "call-1", Codec: "PCMU"}},
		{Protocol: "DNS", DNSData: &types.DNSMetadata{QueryName: "Example.ORG", QueryResponseTimeMs: 1}},
		{Protocol: "TLS", TLSData: &types.TLSMetadata{}},
		{Protocol: "HTTP", HTTPData: &types.HTTPMetadata{}},
		{Protocol: "SMTP", EmailData: &types.EmailMetadata{}},
	}
	var cases []Filter
	for _, field := range []string{"all", "src", "dst", "info", "protocol", "node", "sip.user", "dns.qname", "tls.sni", "unknown"} {
		for _, v := range []string{"", "a", "5060", "INVITE"} {
			cases = append(cases, NewTextFilter(v, []string{field}))
		}
	}
	for _, field := range []string{"length", "dns.latency", "unknown"} {
		for _, v := range []string{"=0", "=1", "=1.00009", "=1.00011", ">=0", "<0", ">0", "<=1", "=NaN", "=+Inf"} {
			f, err := NewNumericComparisonFilter(field, v)
			require.NoError(t, err)
			cases = append(cases, f)
		}
	}
	for _, v := range []string{"tcp", "TCP", "udp", "icmp", "port 5060", "port 05060", "src port 5060", "dst port 0", "host 192.168.1.1", "src host 10.1", "net 192.168.1.0/24", "net 192.168.1.0/99", "NET 10.0.0.0/8", "tcp and port 80", " host 10.1"} {
		f, err := NewBPFFilter(v)
		require.NoError(t, err)
		cases = append(cases, f)
	}
	for _, v := range []string{"voip", "dns", "tls", "http", "email", "unknown"} {
		cases = append(cases, NewMetadataFilter(v))
	}
	for _, v := range []string{"", "*", "edge-*", "*-01", "edge-*-01", "*edge*", "**", "Local"} {
		cases = append(cases, NewNodeFilter(v))
	}
	for _, field := range []string{"user", "from", "to", "method", "callid", "codec", "fromtag", "totag", "unknown"} {
		for _, v := range []string{"", "a", "*a*", "a*", "*a", "a*b"} {
			cases = append(cases, NewVoIPFilter(field, v))
		}
	}
	cases = append(cases, NewCallStateFilter("active"))
	n := len(cases)
	for i := 0; i < n; i++ {
		cases = append(cases, NewBooleanFilter(OpNOT, cases[i], nil, ""), NewBooleanFilter(OpOR, cases[i], NewMetadataFilter("voip"), ""), NewBooleanFilter(OpAND, cases[i], NewNodeFilter("*"), ""))
	}
	for _, f := range cases {
		e, err := CompileOffline(f)
		require.NoError(t, err, f.String())
		require.NotNil(t, e)
		for i, p := range packets {
			require.Equal(t, f.Match(p), e.Match(offline.NewSummary(offline.PacketID(i), p)), "filter %s (%s), packet %d", f.String(), f.Type(), i)
		}
	}
	chain := NewFilterChain()
	chain.Add(NewTextFilter("sip", nil))
	chain.Add(NewMetadataFilter("voip"))
	snapshot, err := chain.OfflineExpression()
	require.NoError(t, err)
	expected := snapshot.Match(offline.NewSummary(0, packets[1]))
	chain.Clear()
	chain.Add(NewNodeFilter("unmatched"))
	require.Equal(t, expected, snapshot.Match(offline.NewSummary(0, packets[1])))
}

// Custom implementations must retain predicate fallback even when their display
// type/text happens to resemble a supported built-in expression.
func TestOfflineExpressionOpaqueFallback(t *testing.T) {
	type customFilter struct{ Filter }
	f := customFilter{NewTextFilter("alice", []string{"info"})}
	e, err := CompileOffline(f)
	require.NoError(t, err)
	require.Nil(t, e)
	chain := NewFilterChain()
	chain.Add(NewMetadataFilter("voip"))
	chain.Add(f)
	e, err = chain.OfflineExpression()
	require.NoError(t, err)
	require.Nil(t, e)
}
