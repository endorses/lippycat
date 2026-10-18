package filterpolicy_test

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func grantSnapshot() *management.PolicySnapshot {
	return &management.PolicySnapshot{ProtocolVersion: 2, Domain: "capture", AuthorityId: "central", Revision: 1, OwnerKind: "shared", ValidFromNs: 1, ValidUntilNs: 100, SourceIds: []string{"hunter"}, SelectionGrants: []*management.CaptureSelectionGrant{{Id: "opaque-reference", Revision: 1, ProcessorId: "processor", Scopes: []*management.CaptureSelectionScope{{HunterId: "hunter", Domain: 0}}, NotBeforeNs: 2, ExpiresAtNs: 99, Purpose: management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA}}}
}
func TestGrantSnapshotVersionBoundsAndSignature(t *testing.T) {
	cfg, key := policyfixture.Config(t)
	v, err := filterpolicy.NewVerifier(cfg)
	require.NoError(t, err)
	signed, err := v.SignSnapshot(key, grantSnapshot())
	require.NoError(t, err)
	require.NoError(t, v.Verify(signed))
	require.Empty(t, signed.Snapshot.Filters)
	mixed := grantSnapshot()
	mixed.Filters = []*management.Filter{{Id: cfg.Namespace() + "ordinary", Type: management.FilterType_FILTER_SIP_URI, Pattern: "ordinary@example.test", Enabled: true}}
	mixedSigned, err := v.SignSnapshot(key, mixed)
	require.NoError(t, err)
	require.NoError(t, v.Verify(mixedSigned), "distributed matching and selection grants coexist without rewriting either")
	require.Len(t, mixedSigned.Snapshot.Filters, 1)
	require.Len(t, mixedSigned.Snapshot.SelectionGrants, 1)
	for _, change := range []func(*management.PolicySnapshot){
		func(s *management.PolicySnapshot) { s.ProtocolVersion = 1 },
		func(s *management.PolicySnapshot) { s.SelectionGrants[0].ExpiresAtNs = 101 },
		func(s *management.PolicySnapshot) { s.SelectionGrants[0].Scopes[0].HunterId = "other" },
		func(s *management.PolicySnapshot) { s.SelectionGrants[0].Purpose = 0 },
		func(s *management.PolicySnapshot) {
			s.SelectionGrants = append(s.SelectionGrants, proto.Clone(s.SelectionGrants[0]).(*management.CaptureSelectionGrant))
		},
	} {
		s := grantSnapshot()
		change(s)
		_, err = v.SignSnapshot(key, s)
		require.ErrorIs(t, err, filterpolicy.ErrInvalid)
	}
	signed.Snapshot.SelectionGrants[0].Revision++
	require.ErrorIs(t, v.Verify(signed), filterpolicy.ErrInvalid)
}
func selectionRule() *management.MediaRule {
	return &management.MediaRule{Id: "rule", Session: &management.MediaRuleSession{ProcessorId: "processor", Generation: 1}, Revision: 1, Call: &management.MediaRuleCall{RegistrySession: 1, RegistryGeneration: 1, CallId: "call", FromTag: "from", ToTag: "to", SelectionRevision: 1, CapturePolicyRevision: 1, SelectionGrants: []*management.CaptureSelectionRef{{Id: "opaque-reference", Revision: 1}}}, Scopes: []*management.MediaRuleScope{{HunterId: "hunter", Domain: 0}}, Endpoints: []*management.MediaRuleEndpoint{{Address: "192.0.2.1", Port: 4000, Kind: management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_RTP}}, NotBeforeNs: 2, ExpiresAtNs: 99}
}
func TestSignedMediaProofBindsEverySelectionFieldAndSurvivesRuleExpiry(t *testing.T) {
	cfg, key := policyfixture.Config(t)
	v, err := filterpolicy.NewVerifier(cfg)
	require.NoError(t, err)
	original := selectionRule()
	signed, err := v.SignMediaRule(key, original)
	require.NoError(t, err)
	require.Empty(t, original.CaptureSignature)
	require.NoError(t, v.VerifyMediaRule(signed), "historical rules remain authentic after expiry")
	for _, change := range []func(*management.MediaRule){
		func(r *management.MediaRule) { r.Session.ProcessorId = "other" }, func(r *management.MediaRule) { r.Call.RegistryGeneration++ }, func(r *management.MediaRule) { r.Call.SelectionGrants[0].Revision++ }, func(r *management.MediaRule) { r.Scopes[0].Domain++ }, func(r *management.MediaRule) { r.Endpoints[0].Port++ }, func(r *management.MediaRule) { r.ExpiresAtNs++ }, func(r *management.MediaRule) { r.Revision++ },
	} {
		r := proto.Clone(signed).(*management.MediaRule)
		change(r)
		require.ErrorIs(t, v.VerifyMediaRule(r), filterpolicy.ErrInvalid)
	}
	wrongCfg, _ := policyfixture.Config(t)
	wrong, err := filterpolicy.NewVerifier(wrongCfg)
	require.NoError(t, err)
	require.ErrorIs(t, wrong.VerifyMediaRule(signed), filterpolicy.ErrInvalid)
}
