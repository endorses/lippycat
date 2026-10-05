package admission

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

// Sequence numbers belong to request initiators, not to media senders. A
// responder that later originates a request therefore uses a separate context.
type derivationSide struct {
	sender, peer, initiator string
}

type derivationState struct {
	cseq                      uint64
	branch, method            string
	complete, hasSDP, missing bool
	rejected                  bool
	accepted                  bool
	digest                    [32]byte
	endpoints                 []mediaadmission.EndpointKey
	previous                  *derivationState
}

func validRecoveryCSeq(result pipeline.SIPResult) bool {
	if result.ResponseCode == 0 && !strings.EqualFold(result.Method, result.CSeqMethod) {
		return false
	}
	if raw, exists := result.Headers["cseq"]; exists {
		fields := strings.Fields(raw)
		if len(fields) != 2 {
			return false
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		return err == nil && n == result.CSeqNumber && strings.EqualFold(fields[1], result.CSeqMethod)
	}
	// Typed callers can supply an already parsed positive sequence. A zero
	// without its validated header is indistinguishable from failed parsing.
	return result.CSeqNumber != 0 && result.CSeqMethod != ""
}

func sideFor(key mediaadmission.DialogKey) (derivationSide, bool) {
	if !key.CSeqValid || key.FromTag == "" || key.Branch == "" || key.CSeqMethod == "" {
		return derivationSide{}, false
	}
	if key.ResponseCode != 0 {
		if key.ToTag == "" {
			return derivationSide{}, false
		}
		return derivationSide{key.ToTag, key.FromTag, key.FromTag}, true
	}
	return derivationSide{key.FromTag, key.ToTag, key.FromTag}, true
}

func derivationCost(side derivationSide, state *derivationState) (int, int) {
	if state == nil {
		return 0, 0
	}
	bytes := 256 + len(side.sender) + len(side.peer) + len(side.initiator) + len(state.branch) + len(state.method) + len(state.endpoints)*128
	endpoints := len(state.endpoints)
	if state.previous != nil {
		priorBytes, priorEndpoints := derivationCost(side, state.previous)
		bytes += priorBytes
		endpoints += priorEndpoints
	}
	return bytes, endpoints
}

// Selected derivation descriptors have their own bounded pool using existing
// pending metadata limits; no negotiation history grows beyond one predecessor.
func (b *Bridge) putDerivation(call *selectedCall, side derivationSide, next *derivationState) bool {
	old := call.derivations[side]
	oldBytes, oldEndpoints := derivationCost(side, old)
	newBytes, newEndpoints := derivationCost(side, next)
	oldCount := 0
	if old != nil {
		oldCount = 1
	}
	if old == nil && len(call.derivations) >= b.cfg.Limits.MaxEndpointsPerOwner {
		call.contextLost = true
		return false
	}
	if err := b.cfg.Metadata.ReserveSelectedDerivation(mediaadmission.SelectedDerivationUsage{Contexts: oldCount, Bytes: oldBytes, Endpoints: oldEndpoints}, mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: newBytes, Endpoints: newEndpoints}); err != nil {
		call.contextLost = true
		return false
	}
	b.storeDerivation(call, side, next)
	b.derivationCount += 1 - oldCount
	b.derivationBytes += newBytes - oldBytes
	b.derivationEndpoints += newEndpoints - oldEndpoints
	return true
}

func (b *Bridge) storeDerivation(call *selectedCall, side derivationSide, next *derivationState) {
	if call.derivations == nil {
		call.derivations = make(map[derivationSide]*derivationState)
	}
	side = derivationSide{strings.Clone(side.sender), strings.Clone(side.peer), strings.Clone(side.initiator)}
	next.branch, next.method = strings.Clone(next.branch), strings.Clone(next.method)
	next.endpoints = append([]mediaadmission.EndpointKey(nil), next.endpoints...)
	call.derivations[side] = next
}

func (b *Bridge) removeDerivation(call *selectedCall, side derivationSide) {
	old := call.derivations[side]
	if old == nil {
		return
	}
	bytes, endpoints := derivationCost(side, old)
	if err := b.cfg.Metadata.ReserveSelectedDerivation(mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: bytes, Endpoints: endpoints}, mediaadmission.SelectedDerivationUsage{}); err != nil {
		logger.Error("Failed to release selected derivation reservation", "error", err)
	}
	b.derivationCount--
	b.derivationBytes -= bytes
	b.derivationEndpoints -= endpoints
	delete(call.derivations, side)
}

func (b *Bridge) releaseDerivations(call *selectedCall) {
	for side := range call.derivations {
		b.removeDerivation(call, side)
	}
}

func sameDerivationEndpoints(a, b []mediaadmission.EndpointKey) bool {
	if len(a) != len(b) {
		return false
	}
	for _, key := range a {
		found := false
		for _, other := range b {
			if key == other {
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

// A tag-bearing message binds only the exact observed initial transaction.
func (b *Bridge) bindEarlyDerivation(call *selectedCall, key mediaadmission.DialogKey) {
	if key.ToTag == "" {
		return
	}
	early := derivationSide{key.FromTag, "", key.FromTag}
	old := call.derivations[early]
	if old == nil || old.cseq != key.CSeq || old.branch != key.Branch || old.method != key.CSeqMethod {
		return
	}
	bound := derivationSide{key.FromTag, key.ToTag, key.FromTag}
	if call.derivations[bound] != nil {
		return
	}
	copy := *old
	// Adding the peer string is charged before releasing the original.
	oldBytes, oldEndpoints := derivationCost(early, old)
	newBytes, newEndpoints := derivationCost(bound, &copy)
	if err := b.cfg.Metadata.ReserveSelectedDerivation(mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: oldBytes, Endpoints: oldEndpoints}, mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: newBytes, Endpoints: newEndpoints}); err != nil {
		call.contextLost = true
		return
	}
	delete(call.derivations, early)
	b.storeDerivation(call, bound, &copy)
	b.derivationBytes += newBytes - oldBytes
	b.derivationEndpoints += newEndpoints - oldEndpoints
}

func (b *Bridge) observeDerivation(call *selectedCall, record mediaadmission.MetadataRecord) bool {
	key := b.bindRequestKey(call, record.Key)
	if !b.negotiationKey(call, key) {
		// Non-negotiation SDP can still contain independently safe endpoints,
		// but cannot repair a missing or unresolved offer/answer context.
		if len(call.derivations) == 0 {
			call.contextLost = true
		}
		return true
	}
	if b.derivationRejected(call, key) {
		return false
	}
	if key.ResponseCode >= 300 {
		return false
	}
	// A provisional response without a dialog tag cannot identify its sender.
	if key.ResponseCode != 0 && key.ToTag == "" && key.DescriptorOnly {
		return false
	}
	side, valid := sideFor(key)
	if !valid {
		call.contextLost = true
		return false
	}
	b.bindEarlyDerivation(call, key)
	old := call.derivations[side]
	next := &derivationState{cseq: key.CSeq, branch: key.Branch, method: key.CSeqMethod, complete: record.Complete, hasSDP: !key.DescriptorOnly, endpoints: record.Endpoints, digest: key.SDPDigest}
	if old != nil {
		if key.CSeq < old.cseq {
			return false
		}
		if key.CSeq == old.cseq {
			if old.rejected {
				return false
			}
			// Descriptors must not erase a body or resolve missing derivation.
			if key.DescriptorOnly {
				return false
			}
			if old.missing || !old.hasSDP {
				if !old.missing && !old.hasSDP && key.ResponseCode == 0 && !b.delayedOfferAnswer(call, side, old, key) {
					next.complete = false
				}
				if (key.Branch != old.branch || key.CSeqMethod != old.method) && !b.delayedOfferAnswer(call, side, old, key) {
					next.complete = false
				}
			} else {
				next.complete = old.complete && next.complete && key.Branch == old.branch && key.CSeqMethod == old.method && old.digest == next.digest && sameDerivationEndpoints(old.endpoints, next.endpoints)
			}
			next.previous = old.previous
			next.accepted = old.accepted
		} else if side.peer == "" && (!old.complete || old.missing) {
			// Without an established dialog a new transaction cannot prove
			// that the original unresolved early offer was superseded.
			call.contextLost = true
		} else {
			next.previous = rollbackDerivation(old)
		}
	}
	b.putDerivation(call, side, next)
	return true
}

// Retain unresolved rollback evidence even when the next observed request is
// complete. A rejected request does not prove that its predecessor was repaired.
// When multiple requests are pending, one unresolved predecessor is retained
// instead of building a transaction history.
func rollbackDerivation(old *derivationState) *derivationState {
	if old.rejected {
		return old.previous
	}
	if old.previous != nil && old.complete && !old.missing && (!old.previous.complete || old.previous.missing) {
		return old.previous
	}
	prior := *old
	prior.previous = nil
	return &prior
}

func (b *Bridge) negotiationKey(call *selectedCall, key mediaadmission.DialogKey) bool {
	if key.CSeqMethod == "INVITE" || key.CSeqMethod == "UPDATE" {
		return true
	}
	if key.CSeqMethod != "ACK" || key.ResponseCode != 0 {
		return false
	}
	side, valid := sideFor(key)
	if !valid {
		return false
	}
	old := call.derivations[side]
	return old != nil && old.cseq == key.CSeq && (old.method == "ACK" || b.delayedOfferAnswer(call, side, old, key))
}

// A successful response retires rollback evidence only for its exact observed
// transaction. Current partial SDP remains partial even after acceptance.
func (b *Bridge) acceptDerivation(call *selectedCall, result pipeline.SIPResult) {
	if result.ResponseCode < 200 || result.ResponseCode >= 300 || !validRecoveryCSeq(result) || (result.CSeqMethod != "INVITE" && result.CSeqMethod != "UPDATE") {
		return
	}
	key := b.key(result, nil)
	if _, valid := sideFor(key); !valid {
		return
	}
	for side, state := range call.derivations {
		if state.rejected || side.initiator != key.FromTag || state.cseq != key.CSeq || state.branch != key.Branch || state.method != key.CSeqMethod || (side.peer != key.ToTag && side.sender != key.ToTag) {
			continue
		}
		next := *state
		next.accepted, next.previous = true, nil
		b.putDerivation(call, side, &next)
	}
}

func (b *Bridge) requireRequestDerivation(call *selectedCall, result pipeline.SIPResult) {
	key := b.key(result, nil)
	b.bindEarlyDerivation(call, key)
	side := derivationSide{key.FromTag, key.ToTag, key.FromTag}
	old := call.derivations[side]
	if old != nil && old.cseq >= key.CSeq {
		if old.cseq == key.CSeq && (old.branch != key.Branch || old.method != key.CSeqMethod) {
			call.contextLost = true
		}
		return
	}
	// With no observed request descriptor an SDP response might be an answer
	// to a lost offer. Keep a repairable missing request, not a known empty set.
	key.ResponseCode, key.DescriptorOnly = 0, false
	if _, valid := sideFor(key); !valid {
		call.contextLost = true
		return
	}
	next := &derivationState{cseq: key.CSeq, branch: key.Branch, method: key.CSeqMethod, hasSDP: true, missing: true}
	if old != nil && old.complete && old.hasSDP {
		prior := *old
		prior.previous = nil
		next.previous = &prior
	}
	b.putDerivation(call, side, next)
}

// Rejected current transactions retain a bounded sequence watermark. Removing
// them entirely would allow a delayed successful response to revive the offer.
func (b *Bridge) rejectDerivation(call *selectedCall, result pipeline.SIPResult) {
	if !validRecoveryCSeq(result) || (result.CSeqMethod != "INVITE" && result.CSeqMethod != "UPDATE") {
		return
	}
	key := b.key(result, nil)
	if key.FromTag == "" || key.Branch == "" {
		call.contextLost = true
		return
	}
	b.bindEarlyDerivation(call, key)
	retired := false
	for side, state := range call.derivations {
		if side.initiator != result.FromTag || state.cseq != result.CSeqNumber || state.branch != result.ViaBranch || state.method != result.CSeqMethod {
			continue
		}
		if side.peer != "" && side.sender != result.ToTag && side.peer != result.ToTag {
			continue
		}
		if !state.rejected {
			if state.accepted {
				call.contextLost = true
				return
			}
			next := &derivationState{cseq: state.cseq, branch: state.branch, method: state.method, complete: true, rejected: true, previous: state.previous}
			b.putDerivation(call, side, next)
		}
		retired = true
	}
	if !retired {
		side := derivationSide{key.FromTag, key.ToTag, key.FromTag}
		old := call.derivations[side]
		if old != nil && old.cseq >= key.CSeq {
			return
		}
		next := &derivationState{cseq: key.CSeq, branch: key.Branch, method: key.CSeqMethod, complete: true, rejected: true}
		if old != nil && old.complete && old.hasSDP {
			prior := *old
			prior.previous = nil
			next.previous = &prior
		}
		b.putDerivation(call, side, next)
	}
	call.known = true
}

func (b *Bridge) derivationRejected(call *selectedCall, key mediaadmission.DialogKey) bool {
	for side, state := range call.derivations {
		if state.rejected && side.initiator == key.FromTag && state.cseq == key.CSeq && state.branch == key.Branch && state.method == key.CSeqMethod && (side.peer == "" || side.peer == key.ToTag || side.sender == key.ToTag) {
			return true
		}
	}
	return false
}

// A late initial request can repair the missing offer established by its exact
// observed response. Never choose a peer from an unrelated branch or fork.
func (b *Bridge) bindRequestKey(call *selectedCall, key mediaadmission.DialogKey) mediaadmission.DialogKey {
	if key.ResponseCode != 0 || key.ToTag != "" {
		return key
	}
	peer := ""
	for side, state := range call.derivations {
		if side.sender != key.FromTag || side.initiator != key.FromTag || side.peer == "" || state.cseq != key.CSeq || state.branch != key.Branch || state.method != key.CSeqMethod {
			continue
		}
		if peer != "" && peer != side.peer {
			call.contextLost = true
			return key
		}
		peer = side.peer
	}
	if peer != "" {
		key.ToTag = peer
	}
	return key
}

func (b *Bridge) delayedOfferAnswer(call *selectedCall, side derivationSide, request *derivationState, key mediaadmission.DialogKey) bool {
	if key.ResponseCode != 0 || key.CSeqMethod != "ACK" || request.method != "INVITE" || request.hasSDP || request.missing || side.peer == "" {
		return false
	}
	response := call.derivations[derivationSide{side.peer, side.sender, side.initiator}]
	return response != nil && !response.rejected && response.hasSDP && response.cseq == key.CSeq && response.branch == request.branch && response.method == "INVITE"
}

func (b *Bridge) derivationSummary(call *selectedCall) (bool, bool, map[mediaadmission.EndpointKey]struct{}) {
	known, unknown := call.known, call.contextLost
	media := make(map[mediaadmission.EndpointKey]struct{})
	for side, state := range call.derivations {
		if state.rejected {
			state = state.previous
			if state == nil {
				continue
			}
		}
		if state.hasSDP {
			known = true
			unknown = unknown || !state.complete || state.missing
		} else if state.method == "INVITE" && side.sender == side.initiator {
			// A bodyless INVITE followed by an SDP response is a delayed
			// offer. Until its ACK answer arrives the initiator's media is
			// unresolved, even though the responder's endpoints are safe.
			response := call.derivations[derivationSide{side.peer, side.sender, side.initiator}]
			if response != nil && response.hasSDP && !response.rejected && response.cseq == state.cseq {
				unknown = true
			}
		}
		for _, endpoint := range state.endpoints {
			media[endpoint] = struct{}{}
		}
	}
	if !known && len(call.derivations) > 0 {
		unknown = true
	}
	return known, unknown, media
}
