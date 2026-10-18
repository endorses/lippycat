package filterpolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"net/netip"
	"sort"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"google.golang.org/protobuf/proto"
)

const SelectionProtocolVersion = 2
const MaxSelectionRefs = 1024
const MaxSelectionIDBytes = 1024
const MaxMediaRuleBytes = 1 << 20

func validSelectionID(id string) bool { return id != "" && len(id) <= MaxSelectionIDBytes }

func validateSelectionGrants(s *management.PolicySnapshot) error {
	if s.ProtocolVersion == 1 && len(s.SelectionGrants) != 0 {
		return ErrInvalid
	}
	if len(s.SelectionGrants) == 0 {
		return nil
	}
	if len(s.SelectionGrants) > maxSnapshotFilters || s.ValidFromNs <= 0 || s.ValidUntilNs <= s.ValidFromNs || len(s.SourceIds) == 0 {
		return ErrInvalid
	}
	sources := make(map[string]bool, len(s.SourceIds))
	priorSource := ""
	for _, id := range s.SourceIds {
		if !validSelectionID(id) || id <= priorSource || sources[id] {
			return ErrInvalid
		}
		sources[id] = true
		priorSource = id
	}
	previous := ""
	for _, g := range s.SelectionGrants {
		if g == nil || !validSelectionID(g.Id) || g.Id <= previous || g.Revision == 0 || !validSelectionID(g.ProcessorId) || g.Purpose != management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA || g.NotBeforeNs < s.ValidFromNs || g.ExpiresAtNs > s.ValidUntilNs || g.ExpiresAtNs <= g.NotBeforeNs || len(g.Scopes) == 0 || len(g.Scopes) > MaxSelectionRefs || len(g.ProtoReflect().GetUnknown()) != 0 {
			return ErrInvalid
		}
		previous = g.Id
		var prior *management.CaptureSelectionScope
		for _, scope := range g.Scopes {
			if scope == nil || !sources[scope.HunterId] || len(scope.ProtoReflect().GetUnknown()) != 0 || (prior != nil && (scope.HunterId < prior.HunterId || (scope.HunterId == prior.HunterId && scope.Domain <= prior.Domain))) {
				return ErrInvalid
			}
			prior = scope
		}
	}
	return nil
}

func canonicalSelectionGrants(s *management.PolicySnapshot) error {
	if len(s.SelectionGrants) > 0 {
		sort.Strings(s.SourceIds)
	}
	for _, g := range s.SelectionGrants {
		if g == nil {
			return ErrInvalid
		}
		for _, scope := range g.Scopes {
			if scope == nil {
				return ErrInvalid
			}
		}
		sort.Slice(g.Scopes, func(i, j int) bool {
			a, b := g.Scopes[i], g.Scopes[j]
			return a.HunterId < b.HunterId || (a.HunterId == b.HunterId && a.Domain < b.Domain)
		})
	}
	sort.Slice(s.SelectionGrants, func(i, j int) bool { return s.SelectionGrants[i].Id < s.SelectionGrants[j].Id })
	return nil
}

// ValidateMediaRuleProof checks the bounded public representation. Source,
// capture-time and current selection authority are checked by its consumer.
func ValidateMediaRuleProof(r *management.MediaRule) error {
	if r == nil || !validSelectionID(r.Id) || r.Session == nil || !validSelectionID(r.Session.ProcessorId) || r.Session.Generation == 0 || r.Revision == 0 || r.Call == nil || r.Call.RegistrySession == 0 || r.Call.RegistryGeneration == 0 || !validSelectionID(r.Call.CallId) || len(r.Call.FromTag) > MaxSelectionIDBytes || len(r.Call.ToTag) > MaxSelectionIDBytes || r.Call.SelectionRevision == 0 || r.Call.CapturePolicyRevision == 0 || len(r.Call.SelectionGrants) == 0 || len(r.Call.SelectionGrants) > MaxSelectionRefs || len(r.Call.FilterIds) > MaxSelectionRefs || len(r.Scopes) == 0 || len(r.Scopes) > MaxSelectionRefs || len(r.Endpoints) == 0 || len(r.Endpoints) > MaxSelectionRefs || r.NotBeforeNs <= 0 || r.ExpiresAtNs <= r.NotBeforeNs || len(r.CaptureSignature) > 16384 || proto.Size(r) > MaxMediaRuleBytes || len(r.ProtoReflect().GetUnknown()) != 0 || len(r.Session.ProtoReflect().GetUnknown()) != 0 || len(r.Call.ProtoReflect().GetUnknown()) != 0 {
		return ErrInvalid
	}
	previous := ""
	for _, ref := range r.Call.SelectionGrants {
		if ref == nil || !validSelectionID(ref.Id) || ref.Id <= previous || ref.Revision == 0 || len(ref.ProtoReflect().GetUnknown()) != 0 {
			return ErrInvalid
		}
		previous = ref.Id
	}
	for _, id := range r.Call.FilterIds {
		if !validSelectionID(id) {
			return ErrInvalid
		}
	}
	scopes := make(map[string]map[uint32]bool)
	for _, scope := range r.Scopes {
		if scope == nil || !validSelectionID(scope.HunterId) || len(scope.ProtoReflect().GetUnknown()) != 0 {
			return ErrInvalid
		}
		if scopes[scope.HunterId] == nil {
			scopes[scope.HunterId] = make(map[uint32]bool)
		}
		if scopes[scope.HunterId][scope.Domain] {
			return ErrInvalid
		}
		scopes[scope.HunterId][scope.Domain] = true
	}
	endpoints := make(map[string]bool)
	for _, ep := range r.Endpoints {
		if ep == nil || ep.Port == 0 || ep.Port > 65535 || ep.Kind < 0 || ep.Kind > management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_MUX || len(ep.ProtoReflect().GetUnknown()) != 0 {
			return ErrInvalid
		}
		addr, err := netip.ParseAddr(ep.Address)
		if err != nil || !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" || addr.Unmap().String() != ep.Address {
			return ErrInvalid
		}
		keyEndpoint := proto.Clone(ep).(*management.MediaRuleEndpoint)
		keyEndpoint.Kind = 0
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(keyEndpoint)
		if err != nil {
			return ErrInvalid
		}
		key := string(encoded)
		if endpoints[key] {
			return ErrInvalid
		}
		endpoints[key] = true
		covered := false
		for _, domains := range scopes {
			if domains[ep.Domain] {
				covered = true
			}
		}
		if !covered {
			return ErrInvalid
		}
	}
	return nil
}

func mediaRuleSignatureInput(r *management.MediaRule) ([]byte, error) {
	copy := proto.Clone(r).(*management.MediaRule)
	copy.CaptureSignature = nil
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(copy)
	if err != nil {
		return nil, err
	}
	return append([]byte("lippycat/capture-selection-media-rule/v2\x00"), b...), nil
}

// SignMediaRule returns an owned signed rule; it never alters the caller's rule.
func (v *Verifier) SignMediaRule(signer crypto.Signer, r *management.MediaRule) (*management.MediaRule, error) {
	if signer == nil || !PublicKeysEqual(signer.Public(), v.certificate.PublicKey) || ValidateMediaRuleProof(r) != nil {
		return nil, ErrInvalid
	}
	copy := proto.Clone(r).(*management.MediaRule)
	copy.CaptureSignature = nil
	input, err := mediaRuleSignatureInput(copy)
	if err != nil {
		return nil, err
	}
	opts := crypto.SignerOpts(crypto.SHA256)
	digest := input
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		opts = crypto.Hash(0)
	} else {
		sum := sha256.Sum256(input)
		digest = sum[:]
	}
	copy.CaptureSignature, err = signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}
	if err = v.VerifyMediaRule(copy); err != nil {
		return nil, err
	}
	return copy, nil
}

// VerifyMediaRule authenticates immutable capture-time proof without consulting
// live call state or rejecting a historical rule solely because it has expired.
func (v *Verifier) VerifyMediaRule(r *management.MediaRule) error {
	if ValidateMediaRuleProof(r) != nil || len(r.CaptureSignature) == 0 || time.Now().Before(v.certificate.NotBefore) || time.Now().After(v.certificate.NotAfter) {
		return ErrInvalid
	}
	input, err := mediaRuleSignatureInput(r)
	if err != nil {
		return ErrInvalid
	}
	algorithm := x509.PureEd25519
	switch v.certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		algorithm = x509.ECDSAWithSHA256
	case *rsa.PublicKey:
		algorithm = x509.SHA256WithRSA
	}
	if v.certificate.CheckSignature(algorithm, input, r.CaptureSignature) != nil {
		return ErrInvalid
	}
	return nil
}
