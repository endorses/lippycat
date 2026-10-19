package learnedrules

import (
	"github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/api/gen/management"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"google.golang.org/protobuf/proto"
)

// BindingFromLegacyCandidate reconstructs immutable capture context from the
// original media artifact. It deliberately does not consult a live store or
// require the captured authority epoch to remain current. The policy owner must
// still authenticate the signature and check capture/output authorization.
func BindingFromLegacyCandidate(candidate *learnedevidence.LearnedCandidate) (core.Binding, *management.MediaRule, error) {
	if candidate == nil || candidate.AdapterId != AdapterID || candidate.ContextVersion != ContextVersion || len(candidate.GetLegacyMediaRule()) == 0 {
		return core.Binding{}, nil, core.ErrInvalid
	}
	encoded := &management.MediaRule{}
	if err := proto.Unmarshal(candidate.GetLegacyMediaRule(), encoded); err != nil {
		return core.Binding{}, nil, core.ErrInvalid
	}
	rule, err := DecodeLegacyRule(encoded)
	if err != nil || len(rule.CaptureSignature) == 0 {
		return core.Binding{}, nil, core.ErrInvalid
	}
	binding := ToBinding(rule)
	if err := Adapter().Validate(binding); err != nil {
		return core.Binding{}, nil, err
	}
	if !wire.ReferenceMatches(candidate, binding) {
		return core.Binding{}, nil, core.ErrInvalid
	}
	// Keep the incoming byte string rather than substituting a re-encoding in
	// retained packet evidence. Semantic identity was checked above.
	binding.Proof = append([]byte(nil), candidate.GetLegacyMediaRule()...)
	return binding, encoded, nil
}
