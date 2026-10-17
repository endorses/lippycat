package filtering

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

func TestDistributionScopeConversionsAndValidation(t *testing.T) {
	for _, scope := range []string{"", "distributed", "local_only"} {
		t.Run(scope, func(t *testing.T) {
			input := &FilterYAML{ID: "test", Type: "sip_user", Pattern: "alice", Enabled: true, DistributionScope: scope}
			f, err := YAMLToProto(input)
			require.NoError(t, err)
			require.Equal(t, scope != "local_only", IsDistributedFilter(f))
			encoded, err := ProtoToJSON(f, false)
			require.NoError(t, err)
			var decoded FilterYAML
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			require.Equal(t, DistributionScopeToString(f.DistributionScope), decoded.DistributionScope)
			listed, err := ProtoSliceToJSON([]*management.Filter{f}, false)
			require.NoError(t, err)
			var listedFilters []FilterYAML
			require.NoError(t, json.Unmarshal(listed, &listedFilters))
			require.Equal(t, decoded.DistributionScope, listedFilters[0].DistributionScope)
			again, err := YAMLToProto(&decoded)
			require.NoError(t, err)
			require.True(t, proto.Equal(f, again))
			persisted := ProtoToYAML(f)
			if scope != "local_only" {
				require.Empty(t, persisted.DistributionScope, "default persistence must retain legacy encoding and bounds")
			}
			data, err := MarshalEncryptedFilters(map[string]*management.Filter{f.Id: f})
			require.NoError(t, err)
			recovered, err := UnmarshalEncryptedFilters(data)
			require.NoError(t, err)
			require.True(t, proto.Equal(f, recovered[f.Id]))
		})
	}
	_, err := ParseDistributionScope("local")
	require.Error(t, err)
	require.Error(t, ValidateFilter(&management.Filter{Id: "x", Pattern: "alice", DistributionScope: management.FilterDistributionScope(27)}))
	require.False(t, IsDistributedFilter(&management.Filter{DistributionScope: management.FilterDistributionScope(27)}))
	var radius FilterYAML
	require.NoError(t, yaml.Unmarshal([]byte("id: x\ntype: radius_username\npattern: alice\nrevision: 1\ndistribution_scope: local_only\n"), &radius))
	f, err := YAMLToProto(&radius)
	require.NoError(t, err)
	require.False(t, IsDistributedFilter(f))
}
