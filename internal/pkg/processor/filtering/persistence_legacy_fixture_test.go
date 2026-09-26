package filtering

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestYAMLPersistenceLegacyFixture(t *testing.T) {
	persistence := NewYAMLPersistence()
	t.Cleanup(func() { require.NoError(t, persistence.Close()) })
	fixture, err := os.ReadFile(filepath.Join("testdata", "legacy_filters.yaml"))
	require.NoError(t, err)
	path := filepath.Join(privateStoreTestDir(t), "filters.yaml")
	require.NoError(t, os.WriteFile(path, fixture, 0600))
	filters, err := persistence.Load(path)
	require.NoError(t, err)
	// Explicitly cover every legacy managed filter type, including enum-name input.
	expected := []struct {
		id      string
		typeID  management.FilterType
		pattern string
	}{
		{"sip-user", management.FilterType_FILTER_SIP_USER, "fixture-user"},
		{"phone-number", management.FilterType_FILTER_PHONE_NUMBER, "+15550100123"},
		{"ip-address", management.FilterType_FILTER_IP_ADDRESS, "192.0.2.0/24"},
		{"call-id", management.FilterType_FILTER_CALL_ID, "synthetic-call@example.invalid"},
		{"codec", management.FilterType_FILTER_CODEC, "PCMU"},
		{"bpf", management.FilterType_FILTER_BPF, "udp port 5060"},
		{"sip-uri", management.FilterType_FILTER_SIP_URI, "sip:fixture@example.invalid"},
		{"imsi", management.FilterType_FILTER_IMSI, "001010000000001"},
		{"imei", management.FilterType_FILTER_IMEI, "000000000000001"},
		{"dns-domain", management.FilterType_FILTER_DNS_DOMAIN, "*.example.invalid"},
		{"email-address", management.FilterType_FILTER_EMAIL_ADDRESS, "fixture@example.invalid"},
		{"email-subject", management.FilterType_FILTER_EMAIL_SUBJECT, "Synthetic fixture subject"},
		{"tls-sni", management.FilterType_FILTER_TLS_SNI, "mdf.example.invalid"},
		{"tls-ja3", management.FilterType_FILTER_TLS_JA3, "0123456789abcdef0123456789abcdef"},
		{"tls-ja3s", management.FilterType_FILTER_TLS_JA3S, "fedcba9876543210fedcba9876543210"},
		{"tls-ja4", management.FilterType_FILTER_TLS_JA4, "t13d1516h2_8daaf6152771_b186095e22bb"},
		{"http-host", management.FilterType_FILTER_HTTP_HOST, "fixture.example.invalid"},
		{"http-url", management.FilterType_FILTER_HTTP_URL, "/synthetic/*"},
		{"radius-username", management.FilterType_FILTER_RADIUS_USERNAME, "Fixture@example.invalid"},
		{"radius-mac", management.FilterType_FILTER_RADIUS_MAC, "02-00-00-00-00-01"},
		{"radius-attribute", management.FilterType_FILTER_RADIUS_ATTRIBUTE, "570361"},
		{"radius-compound", management.FilterType_FILTER_RADIUS_COMPOUND, ""},
	}
	require.Len(t, filters, len(expected), "legacy records must not be skipped")
	for _, want := range expected {
		f := filters["fixture-"+want.id]
		require.NotNil(t, f, want.id)
		require.Equal(t, "fixture-"+want.id, f.Id)
		require.Equal(t, want.typeID, f.Type)
		require.Equal(t, want.pattern, f.Pattern)
		require.Equal(t, want.id != "phone-number", f.Enabled)
	}
	require.Equal(t, uint64(17), filters["fixture-sip-user"].Revision)
	require.Equal(t, []string{"fixture-edge-a", "fixture-edge-b"}, filters["fixture-sip-user"].TargetHunters)
	require.Equal(t, "Synthetic editable filter", filters["fixture-sip-user"].Description)
	require.Zero(t, filters["fixture-phone-number"].Revision)
	require.Empty(t, filters["fixture-phone-number"].TargetHunters)
	for i, id := range []string{"username", "mac", "attribute"} {
		require.Equal(t, uint64(19+i), filters["fixture-radius-"+id].Revision)
	}
	scope := &management.RadiusScopeBinding{OperatorScope: "fixture-operator/nas", ProfileRevision: "fixture-v1", OriginNodeId: "fixture-edge-a", SourceId: "fixture-eth0"}
	require.True(t, proto.Equal(scope, filters["fixture-radius-attribute"].Radius.Scope))
	compound := filters["fixture-radius-compound"]
	require.Equal(t, uint64(23), compound.Revision)
	require.Equal(t, []string{"fixture-edge-a"}, compound.TargetHunters)
	require.Equal(t, "Synthetic conjunctive LI RADIUS selector", compound.Description)
	wantRadius := &management.RadiusFilterCriteria{
		GroupId: "fixture-radius-group", TaskId: "33333333-3333-4333-8333-333333333333",
		TaskGeneration: 31, Scope: scope,
		Criteria: []*management.RadiusCriterion{
			{FilterId: "fixture-radius-user-criterion", FilterRevision: 23, Kind: "username", Value: "Fixture@example.invalid", TargetKind: "nai"},
			{FilterId: "fixture-radius-mac-criterion", FilterRevision: 23, Kind: "mac", Value: "02-00-00-00-00-01", MacProfile: "calling-station-id-uppercase-hyphen-v1", TargetKind: "mac"},
			{FilterId: "fixture-radius-line-criterion", FilterRevision: 23, Kind: "attribute", Value: "570361", TargetKind: "line"},
		},
	}
	require.True(t, proto.Equal(wantRadius, compound.Radius), "compound ownership, scope, revisions and conjunction must all survive")

	// Editable YAML writes must retain all protobuf data represented by the fixture.
	require.NoError(t, persistence.Save(path, filters))
	reloaded, err := persistence.Load(path)
	require.NoError(t, err)
	require.Len(t, reloaded, len(filters))
	for id, want := range filters {
		require.True(t, proto.Equal(want, reloaded[id]), id)
	}
}
