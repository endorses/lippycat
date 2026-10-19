package wire

import (
	pb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"slices"
)

// Capabilities are bounded, exact contracts, never wildcard approximations.
func ValidateCapabilities(caps []*pb.LearnedCapability) error {
	if len(caps) == 0 || len(caps) > 64 {
		return learnedrules.ErrUnsupported
	}
	seen := map[string]map[uint32]bool{}
	for _, c := range caps {
		if c == nil || len(c.ProtoReflect().GetUnknown()) != 0 || c.AdapterId == "" || len(c.AdapterId) > 128 || c.ContextVersion == 0 || len(c.EndpointSelectorVersions) != 1 || c.EndpointSelectorVersions[0] != EndpointSelectorVersion || len(c.EvidenceVersions) != 1 || c.EvidenceVersions[0] != EvidenceVersion || len(c.Qualifiers) > 64 {
			return learnedrules.ErrUnsupported
		}
		if len(c.SupportedProtocols) > 2 {
			return learnedrules.ErrUnsupported
		}
		protocols := make(map[uint32]bool)
		for _, protocol := range c.SupportedProtocols {
			if protocol != uint32(learnedrules.UDP) && protocol != uint32(learnedrules.TCP) || protocols[protocol] {
				return learnedrules.ErrUnsupported
			}
			protocols[protocol] = true
		}
		if seen[c.AdapterId] == nil {
			seen[c.AdapterId] = map[uint32]bool{}
		}
		if seen[c.AdapterId][c.ContextVersion] {
			return learnedrules.ErrInvalid
		}
		seen[c.AdapterId][c.ContextVersion] = true
		quals := map[learnedrules.Qualifier]bool{}
		for _, q := range c.Qualifiers {
			if q == nil || len(q.ProtoReflect().GetUnknown()) != 0 || q.Id == "" || len(q.Id) > 128 || q.Version == 0 {
				return learnedrules.ErrUnsupported
			}
			key := learnedrules.Qualifier{ID: q.Id, Version: q.Version}
			if quals[key] {
				return learnedrules.ErrInvalid
			}
			quals[key] = true
		}
	}
	return nil
}
func Supports(caps []*pb.LearnedCapability, b learnedrules.Binding) bool {
	if !EvidenceRepresentable(b) {
		return false
	}
	for _, c := range caps {
		if c.AdapterId != b.AdapterID || c.ContextVersion != b.ContextVersion {
			continue
		}
		for _, selector := range b.Selectors {
			if len(c.SupportedProtocols) > 0 && !slices.Contains(c.SupportedProtocols, uint32(selector.Protocol)) {
				return false
			}
			if selector.Qualifier.ID == "" {
				continue
			}
			found := false
			for _, q := range c.Qualifiers {
				if q.Id == selector.Qualifier.ID && q.Version == selector.Qualifier.Version {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	return false
}
func cloneCapabilities(caps []*pb.LearnedCapability) []*pb.LearnedCapability {
	out := make([]*pb.LearnedCapability, len(caps))
	for i, c := range caps {
		out[i] = proto.Clone(c).(*pb.LearnedCapability)
	}
	return out
}
func equalCapabilities(a, b []*pb.LearnedCapability) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !proto.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// LegacyFallbackAllowed is deliberately narrow. Authentication, malformed data,
// failed installation, and scope/proof failures never trigger a downgrade. The
// caller must additionally prove exact VoIP representability; other adapters
// cannot use a legacy service.
func LegacyFallbackAllowed(err error, exactlyRepresentableVoIP bool) bool {
	return exactlyRepresentableVoIP && status.Code(err) == codes.Unimplemented
}
