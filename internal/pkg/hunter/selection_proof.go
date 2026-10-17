//go:build hunter || tap || all

package hunter

import (
	"crypto/sha256"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	"github.com/google/gopacket"
	"google.golang.org/protobuf/proto"
	"sort"
)

const unfilteredSelection = "\x00unfiltered"

func (af *ApplicationFilter) updateSelectionFingerprintsLocked(filters []*management.Filter) {
	af.selectionFingerprints = make(map[string][32]byte)
	for _, filter := range filters {
		if filter == nil {
			continue
		}
		semantic := proto.Clone(filter).(*management.Filter)
		semantic.Description = ""
		semantic.Revision = 0
		sort.Strings(semantic.TargetHunters)
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(semantic)
		if err != nil {
			panic(err)
		} // generated filter messages contain no fallible custom marshalers
		af.selectionFingerprints[filter.Id] = sha256.Sum256(encoded)
	}
}

func (af *ApplicationFilter) unfilteredFingerprintLocked() [32]byte {
	return sha256.Sum256([]byte("unfiltered:" + string(af.noFilterPolicy)))
}

func (af *ApplicationFilter) MatchPacketWithSelectionProof(packet gopacket.Packet) (bool, []string, capturepolicy.FilterSelectionProof) {
	af.mu.RLock()
	defer af.mu.RUnlock()
	matched, ids := af.matchPacketLocked(packet, packetMatchFull, true)
	if !matched {
		return false, ids, nil
	}
	proof := make(capturepolicy.FilterSelectionProof)
	for _, id := range ids {
		if fingerprint, ok := af.selectionFingerprints[id]; ok {
			proof[id] = fingerprint
		}
	}
	if len(ids) == 0 && len(af.selectionFingerprints) == 0 && af.noFilterPolicy == NoFilterPolicyAllow {
		proof[unfilteredSelection] = af.unfilteredFingerprintLocked()
	}
	return matched, ids, proof
}

func (af *ApplicationFilter) CurrentSelection(proof capturepolicy.FilterSelectionProof) (bool, []string) {
	af.mu.RLock()
	defer af.mu.RUnlock()
	var ids []string
	for id, fingerprint := range proof {
		if id == unfilteredSelection {
			if len(af.selectionFingerprints) == 0 && af.noFilterPolicy == NoFilterPolicyAllow && fingerprint == af.unfilteredFingerprintLocked() {
				return true, nil
			}
		} else if current, ok := af.selectionFingerprints[id]; ok && current == fingerprint {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return len(ids) != 0, ids
}
