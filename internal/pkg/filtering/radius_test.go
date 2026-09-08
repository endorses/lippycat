package filtering

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

func TestRADIUSStructuredRoundTrip(t *testing.T) {
	f := &management.Filter{Id: "compound", Type: management.FilterType_FILTER_RADIUS_COMPOUND, Enabled: true, Revision: 9, Radius: &management.RadiusFilterCriteria{GroupId: "group", TaskId: "task", TaskGeneration: 3, Scope: &management.RadiusScopeBinding{OperatorScope: "operator/nas", ProfileRevision: "v1", OriginNodeId: "hunter", SourceId: "eth0"}, Criteria: []*management.RadiusCriterion{{FilterId: "username", FilterRevision: 9, Kind: "username", Value: "User@Realm", TargetKind: "nai"}, {FilterId: "line", FilterRevision: 9, Kind: "attribute", Value: "570361", TargetKind: "line"}}}}
	require.NoError(t, ValidateFilter(f))
	encoded, err := yaml.Marshal(ProtoToYAML(f))
	require.NoError(t, err)
	var decoded FilterYAML
	require.NoError(t, yaml.Unmarshal(encoded, &decoded))
	actual, err := YAMLToProto(&decoded)
	require.NoError(t, err)
	require.True(t, proto.Equal(f, actual))
	raw, err := proto.Marshal(f)
	require.NoError(t, err)
	var restored management.Filter
	require.NoError(t, proto.Unmarshal(raw, &restored))
	require.True(t, proto.Equal(f, &restored))
	restored.Radius.Criteria[1].Value = "5704"
	require.Error(t, ValidateFilter(&restored))
}

func TestRADIUSValidation(t *testing.T) {
	for _, name := range []string{"radius_username", "radius_mac", "radius_attribute", "radius_compound"} {
		ft, err := ParseFilterType(name)
		require.NoError(t, err)
		require.Equal(t, name, FilterTypeToString(ft))
		require.NoError(t, ValidateFilterType(name))
	}
	f := &management.Filter{Id: "mac", Revision: 1, Type: management.FilterType_FILTER_RADIUS_MAC, Pattern: "AA-BB-CC-DD-EE-FF"}
	require.Error(t, ValidateFilter(f))
	f.Radius = &management.RadiusFilterCriteria{MacProfile: radius.MACProfileUppercaseHyphen}
	require.NoError(t, ValidateFilter(f))
	f.Type = management.FilterType_FILTER_IP_ADDRESS
	require.Error(t, ValidateFilter(f))
	f = &management.Filter{Id: "line", Revision: 1, Type: management.FilterType_FILTER_RADIUS_ATTRIBUTE, Pattern: "570361", Radius: &management.RadiusFilterCriteria{Scope: &management.RadiusScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}}
	p, g, err := CompileRADIUSFilter(f)
	require.NoError(t, err)
	require.Nil(t, p)
	require.NotNil(t, g)
	f.Revision = 0
	require.Error(t, ValidateFilter(f))
}

func TestRADIUSYAMLRejectsMisspelledScope(t *testing.T) {
	var f FilterYAML
	err := yaml.Unmarshal([]byte("id: x\ntype: radius_username\npattern: alice\nradius:\n  scope:\n    operator_scope: op\n    profile_revision: v1\n    origin_node: silently-dropped\n"), &f)
	require.Error(t, err)
}

func TestRADIUSPersistenceRejectsMalformedCriteria(t *testing.T) {
	path := t.TempDir() + "/filters.yaml"
	f := &management.Filter{Id: "bad", Revision: 1, Type: management.FilterType_FILTER_RADIUS_ATTRIBUTE, Pattern: "5704", Enabled: true}
	require.NoError(t, WriteFile(path, map[string]*management.Filter{"bad": f}))
	_, err := ParseFile(path)
	require.Error(t, err)
	_, _, err = ParseFileWithErrors(path)
	require.Error(t, err)
	var decoded FilterYAML
	require.Error(t, yaml.Unmarshal([]byte("id: x\nrevision: 1\ntype: radius_username\npattern: alice\nraduis:\n  scope: operator\n"), &decoded))
}
