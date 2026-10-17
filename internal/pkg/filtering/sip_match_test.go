package filtering

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

func sipFilter(id string, kind management.FilterType, pattern string) *management.Filter {
	return &management.Filter{Id: id, Type: kind, Pattern: pattern, Enabled: true}
}
func parsedSIP(t *testing.T, identityHeader string) sip.Event {
	t.Helper()
	message := "INVITE sip:recipient@example.net SIP/2.0\r\nFrom: <sip:originator@example.org>;tag=from\r\nTo: <sip:recipient@example.net>\r\nCall-ID: Call-Exact@host\r\nCSeq: 1 INVITE\r\n" + identityHeader + "Content-Length: 0\r\n\r\n"
	event, err := sip.Parse([]byte(message), sip.ParseOptions{SourceIP: "192.0.2.7", DestinationIP: "2001:db8::7"})
	require.NoError(t, err)
	return event
}
func TestMatchSIPUsesAllIdentityHeadersAndExistingPatternSemantics(t *testing.T) {
	for _, header := range []string{"From", "To", "P-Asserted-Identity", "P-Preferred-Identity", "P-Called-Party-ID", "Request-URI"} {
		t.Run(header, func(t *testing.T) {
			event := parsedSIP(t, "")
			value := "\"Alice\" <sip:ALICE-USER@EXAMPLE.COM>"
			switch header {
			case "From":
				event.From = value
			case "To":
				event.To = value
			case "P-Asserted-Identity":
				event.PAssertedIdentity = value
			case "Request-URI":
				event.RequestURI = "sip:ALICE-USER@EXAMPLE.COM"
			default:
				event.Headers[strings.ToLower(header)] = value
			}
			ids, err := MatchSIP(event, []*management.Filter{
				sipFilter("contains", management.FilterType_FILTER_SIP_USER, "ice-us"),
				sipFilter("prefix", management.FilterType_FILTER_SIP_USER, "alice*"),
				sipFilter("suffix", management.FilterType_FILTER_SIP_USER, "*user"),
				sipFilter("uri", management.FilterType_FILTER_SIP_URI, "alice-user@example.com"),
				sipFilter("other", management.FilterType_FILTER_SIP_USER, "somebodyelse"),
			}, "edge-a")
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"contains", "prefix", "suffix", "uri"}, ids)
		})
	}
}
func TestMatchSIPUsesParsedCompactAndFoldedHeaders(t *testing.T) {
	event, err := sip.Parse([]byte("INVITE sip:recipient@example.net SIP/2.0\r\nf: <sip:originator@example.org>;tag=from\r\nt: <sip:recipient@example.net>\r\ni: a-call\r\nP-Preferred-Identity: Alice\r\n <sip:alice@example.com>\r\nl: 0\r\n\r\n"), sip.ParseOptions{})
	require.NoError(t, err)
	ids, err := MatchSIP(event, []*management.Filter{sipFilter("alice", management.FilterType_FILTER_SIP_USER, "alice")}, "edge-a")
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, ids)
}
func TestMatchSIPPhoneSuffixNormalizationAndShortNumberRules(t *testing.T) {
	event := parsedSIP(t, "P-Asserted-Identity: <sip:+49-1234567890@operator.example>\r\n")
	filters := []*management.Filter{
		sipFilter("full", management.FilterType_FILTER_PHONE_NUMBER, "00491234567890"),
		sipFilter("national", management.FilterType_FILTER_PHONE_NUMBER, "1234567890"),
		sipFilter("short-exact", management.FilterType_FILTER_PHONE_NUMBER, "567890"),
		sipFilter("short-wildcard", management.FilterType_FILTER_PHONE_NUMBER, "*567890"),
		sipFilter("formatted-wildcard", management.FilterType_FILTER_PHONE_NUMBER, "+49*"),
	}
	ids, err := MatchSIP(event, filters, "edge-a")
	require.NoError(t, err)
	// Pure-digit patterns normalize the observed number and use the established
	// minimum suffix length. Explicit wildcard matching uses the SIP user text,
	// just as the hunter AC path does; it does not remove its '+' punctuation.
	require.ElementsMatch(t, []string{"full", "national", "short-wildcard"}, ids)
}
func TestMatchSIPScopesAndIndependentMatchingFilters(t *testing.T) {
	event := parsedSIP(t, "P-Asserted-Identity: <sip:alice@example.com>\r\n")
	scoped := sipFilter("distributed", management.FilterType_FILTER_SIP_USER, "alice")
	scoped.TargetHunters = []string{"edge-a"}
	local := sipFilter("local", management.FilterType_FILTER_SIP_USER, "alice")
	local.DistributionScope = management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY
	local.TargetHunters = []string{"elsewhere"}
	disabled := sipFilter("disabled", management.FilterType_FILTER_SIP_USER, "alice")
	disabled.Enabled = false
	same := sipFilter("another-task", management.FilterType_FILTER_SIP_USER, "alice")
	filters := []*management.Filter{scoped, local, disabled, same, sipFilter("unrelated", management.FilterType_FILTER_DNS_DOMAIN, "alice")}
	ids, err := MatchSIP(event, filters, "edge-b")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"local", "another-task"}, ids)
	ids, err = MatchSIP(event, filters, "edge-a")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"distributed", "local", "another-task"}, ids)
	_, err = MatchSIP(event, filters, "")
	require.ErrorIs(t, err, ErrSIPSource)
}
func TestMatchSIPPacketIPAndExactOpaqueCallID(t *testing.T) {
	event := parsedSIP(t, "")
	filters := []*management.Filter{
		sipFilter("ip", management.FilterType_FILTER_IP_ADDRESS, "192.0.2.7"),
		sipFilter("cidr", management.FilterType_FILTER_IP_ADDRESS, "192.0.2.0/24"),
		sipFilter("v6", management.FilterType_FILTER_IP_ADDRESS, "2001:db8::/32"),
		sipFilter("call", management.FilterType_FILTER_CALL_ID, "Call-Exact@host"),
		sipFilter("call-case", management.FilterType_FILTER_CALL_ID, "call-exact@host"),
		sipFilter("call-substring", management.FilterType_FILTER_CALL_ID, "Exact"),
		sipFilter("other-ip", management.FilterType_FILTER_IP_ADDRESS, "198.51.100.0/24"),
	}
	ids, err := MatchSIP(event, filters, "edge-a")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"ip", "cidr", "v6", "call"}, ids)
	event.SourceIP = "::ffff:192.0.2.7"
	ids, err = MatchSIP(event, filters, "edge-a")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"ip", "cidr", "v6", "call"}, ids)
	event.SourceIP = "not-an-ip"
	_, err = MatchSIP(event, filters, "edge-a")
	require.ErrorIs(t, err, ErrSIPEvent)
	// SDP/body or a SIP identity's host is never used as packet-IP evidence.
	event.SourceIP = ""
	event.DestinationIP = ""
	event.From = "<sip:alice@192.0.2.7>"
	event.Body = []byte("c=IN IP4 192.0.2.7")
	ids, err = MatchSIP(event, filters, "edge-a")
	require.NoError(t, err)
	require.Equal(t, []string{"call"}, ids)
}
func TestSIPMatcherIsDetachedAndCurrentSnapshotReplacesSelection(t *testing.T) {
	event := parsedSIP(t, "P-Asserted-Identity: <sip:alice@example.com>\r\n")
	filter := sipFilter("select", management.FilterType_FILTER_SIP_USER, "alice")
	filter.TargetHunters = []string{"edge-a"}
	compiled, err := CompileSIPFilters([]*management.Filter{filter})
	require.NoError(t, err)
	filter.Pattern = "bob"
	filter.TargetHunters[0] = "edge-b"
	ids, err := compiled.Match(event, "edge-a")
	require.NoError(t, err)
	require.Equal(t, []string{"select"}, ids)
	replacement, err := CompileSIPFilters([]*management.Filter{filter})
	require.NoError(t, err)
	ids, err = replacement.Match(event, "edge-a")
	require.NoError(t, err)
	require.Empty(t, ids)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				ids, err := compiled.Match(event, "edge-a")
				if err != nil || len(ids) != 1 {
					t.Errorf("immutable matcher changed: ids=%v err=%v", ids, err)
				}
			}
		}()
	}
	wg.Wait()
}
func TestSIPMatcherRejectsInvalidPolicyAndBoundsInputs(t *testing.T) {
	for name, filters := range map[string][]*management.Filter{
		"nil":       {nil},
		"duplicate": {sipFilter("same", management.FilterType_FILTER_SIP_USER, "alice"), sipFilter("same", management.FilterType_FILTER_SIP_USER, "bob")},
		"ip":        {sipFilter("ip", management.FilterType_FILTER_IP_ADDRESS, "bad-ip")},
		"empty":     {sipFilter("empty", management.FilterType_FILTER_SIP_USER, "")},
		"long":      {sipFilter("long", management.FilterType_FILTER_SIP_USER, strings.Repeat("a", MaxManagedStringBytes+1))},
	} {
		t.Run(name, func(t *testing.T) { _, err := CompileSIPFilters(filters); require.ErrorIs(t, err, ErrSIPFilter) })
	}
	unknown := sipFilter("scope", management.FilterType_FILTER_SIP_USER, "alice")
	unknown.DistributionScope = management.FilterDistributionScope(99)
	_, err := CompileSIPFilters([]*management.Filter{unknown})
	require.ErrorIs(t, err, ErrSIPFilter)
	_, err = CompileSIPFilters(make([]*management.Filter, MaxManagedFilters+1))
	require.ErrorIs(t, err, ErrSIPFilter)
	matcher, err := CompileSIPFilters([]*management.Filter{sipFilter("alice", management.FilterType_FILTER_SIP_USER, "alice")})
	require.NoError(t, err)
	event := parsedSIP(t, "")
	event.From = strings.Repeat("a", sip.MaxMessageSize+1)
	_, err = matcher.Match(event, "edge-a")
	require.ErrorIs(t, err, ErrSIPEvent)
	// Exact duplicates of a phone pattern must not lose independent filter IDs.
	event = parsedSIP(t, "P-Asserted-Identity: <sip:+491234567890@example.com>\r\n")
	var filters []*management.Filter
	for i := range 3 {
		filters = append(filters, sipFilter(fmt.Sprint(i), management.FilterType_FILTER_PHONE_NUMBER, "1234567890"))
	}
	ids, err := MatchSIP(event, filters, "edge-a")
	require.NoError(t, err)
	require.Len(t, ids, 3)
}
