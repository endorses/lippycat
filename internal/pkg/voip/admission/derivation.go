package admission

import (
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

// Sequence numbers belong to request initiators, not to media senders. A
// responder that later originates a request therefore uses a separate context.
// An empty initiator reserves a context for independently safe non-negotiation
// endpoints; it never supplies transaction or offer/answer proof.
type derivationSide struct {
	sender, peer, initiator string
	prack                   bool
}

type derivationState struct {
	cseq                      uint64
	branch, method            string
	complete, hasSDP, missing bool
	rejected                  bool
	accepted                  bool
	dialogConfirmed           bool
	recoveryEligible          bool
	recoveryPending           bool
	digest                    [32]byte
	endpoints                 []mediaadmission.EndpointKey
	retirementEndpoints       []mediaadmission.EndpointKey
	previous                  *derivationState
	responseCode              int
	reliable                  bool
	rseq                      uint32
	rackValid                 bool
	rackRSeq, rackCSeq        uint32
	proofExpires              time.Time
	reliableAnswered          bool
	prackCSeq                 uint64
	prackBranch               string
}

func validRecoveryCSeq(result pipeline.SIPResult) bool {
	if result.DuplicateReliableHeaders.CSeq {
		return false
	}
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
		return derivationSide{key.ToTag, key.FromTag, key.FromTag, false}, true
	}
	return derivationSide{key.FromTag, key.ToTag, key.FromTag, false}, true
}

func derivationCost(side derivationSide, state *derivationState) (int, int) {
	if state == nil {
		return 0, 0
	}
	endpoints := len(state.endpoints) + len(state.retirementEndpoints)
	bytes := 376 + len(side.sender) + len(side.peer) + len(side.initiator) + len(state.branch) + len(state.method) + len(state.prackBranch) + endpoints*128
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
	if old != nil && next.cseq > old.cseq {
		requestSide := side
		requestSide.prack = false
		if side.sender != side.initiator {
			requestSide = derivationSide{side.initiator, side.sender, side.initiator, false}
		}
		request := call.derivations[requestSide]
		established := old.dialogConfirmed || old.recoveryEligible || (request != nil && (request.dialogConfirmed || request.recoveryEligible))
		if established && !b.retainRetirementEndpoints(call, next, old) {
			return false
		}
	}
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
	side = derivationSide{strings.Clone(side.sender), strings.Clone(side.peer), strings.Clone(side.initiator), side.prack}
	next.branch, next.method = strings.Clone(next.branch), strings.Clone(next.method)
	next.prackBranch = strings.Clone(next.prackBranch)
	next.endpoints = append([]mediaadmission.EndpointKey(nil), next.endpoints...)
	next.retirementEndpoints = append([]mediaadmission.EndpointKey(nil), next.retirementEndpoints...)
	call.derivations[side] = next
}

// Preserve endpoint provenance when the single rollback predecessor advances.
// These keys are not current media or transaction proof. Their bounded charge
// survives until confirmed supersession can release their registry ownership.
func (b *Bridge) retainRetirementEndpoints(call *selectedCall, next, old *derivationState) bool {
	keys := append([]mediaadmission.EndpointKey(nil), old.retirementEndpoints...)
	keys = append(keys, old.endpoints...)
	if old.previous != nil {
		keys = append(keys, old.previous.endpoints...)
		keys = append(keys, old.previous.retirementEndpoints...)
	}
	retained := make(map[mediaadmission.EndpointKey]bool)
	for _, key := range next.endpoints {
		retained[key] = true
	}
	if next.previous != nil {
		for _, key := range next.previous.endpoints {
			retained[key] = true
		}
	}
	obsolete := make([]mediaadmission.EndpointKey, 0, len(keys))
	for _, key := range keys {
		if !retained[key] {
			retained[key] = true
			obsolete = append(obsolete, key)
			if len(obsolete) > b.cfg.Limits.MaxEndpointsPerOwner {
				call.contextLost = true
				return false
			}
		}
	}
	next.retirementEndpoints = obsolete
	return true
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
	early := derivationSide{key.FromTag, "", key.FromTag, false}
	old := call.derivations[early]
	if old == nil || old.cseq != key.CSeq || old.branch != key.Branch || old.method != key.CSeqMethod {
		return
	}
	bound := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
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
	if key.CSeqMethod == "PRACK" && key.ResponseCode == 0 {
		return b.observePRACK(call, record)
	}
	if key.CSeqMethod == "PRACK" && !key.DescriptorOnly {
		call.contextLost = true // SDP in the PRACK response has an unsupported role.
		return true
	}
	if !b.negotiationKey(call, key) {
		if key.CSeqMethod == "ACK" && key.ResponseCode == 0 {
			side, valid := sideFor(key)
			if valid {
				response := call.derivations[derivationSide{side.peer, side.sender, side.initiator, false}]
				if response != nil && response.reliable && response.cseq == key.CSeq {
					return false // ACK cannot supply the missing PRACK answer.
				}
			}
		}
		// Non-negotiation SDP can still contain independently safe endpoints,
		// but cannot repair a missing or unresolved offer/answer context.
		if len(call.derivations) == 0 {
			call.contextLost = true
		}
		if len(record.Endpoints) > 0 {
			side := derivationSide{key.FromTag, key.ToTag, "", false}
			if key.ResponseCode != 0 {
				side.sender, side.peer = side.peer, side.sender
			}
			next := &derivationState{complete: true, hasSDP: true}
			if old := call.derivations[side]; old != nil {
				next.endpoints = append(next.endpoints, old.endpoints...)
			}
			next.endpoints = append(next.endpoints, record.Endpoints...)
			next.endpoints = uniqueEndpoints(next.endpoints, b.cfg.Limits.MaxEndpointsPerOwner+1)
			if len(next.endpoints) > b.cfg.Limits.MaxEndpointsPerOwner {
				call.contextLost = true
				return false
			}
			return b.putDerivation(call, side, next)
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
	next := &derivationState{cseq: key.CSeq, branch: key.Branch, method: key.CSeqMethod, complete: record.Complete, hasSDP: !key.DescriptorOnly, endpoints: record.Endpoints, digest: key.SDPDigest, responseCode: key.ResponseCode, reliable: key.ReliableResponse, rseq: key.RSeq, proofExpires: time.Now().Add(b.cfg.Limits.PendingTTL)}
	if old != nil {
		next.dialogConfirmed = old.dialogConfirmed
		next.recoveryEligible = old.recoveryEligible
		next.recoveryPending = old.recoveryPending
		next.retirementEndpoints = old.retirementEndpoints
		if key.CSeq < old.cseq {
			return false
		}
		if key.CSeq == old.cseq {
			if old.rejected {
				return false
			}
			// Descriptors must not erase a body or resolve missing derivation.
			if key.DescriptorOnly {
				if old.missing && key.ResponseCode == 0 && key.CSeqMethod == "INVITE" && key.Branch == old.branch {
					next.previous, next.accepted = old.previous, old.accepted
					b.putDerivation(call, side, next)
					return true
				}
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
			// A final SDP retransmission may repeat the reliable offer, but
			// cannot replace its exact response linkage or its matched answer.
			if old.reliable && key.ResponseCode >= 200 && old.digest == next.digest {
				next.reliable, next.rseq, next.proofExpires = old.reliable, old.rseq, old.proofExpires
			} else if old.hasSDP && (old.reliable != next.reliable || old.rseq != next.rseq) {
				next.complete = false
			}
			next.previous = old.previous
			next.accepted = old.accepted
			next.reliableAnswered = old.reliableAnswered
			next.prackCSeq, next.prackBranch = old.prackCSeq, old.prackBranch
			if old.reliable {
				next.proofExpires = old.proofExpires
			}
		} else if side.peer == "" && (!old.complete || old.missing) {
			// Without an established dialog a new transaction cannot prove
			// that the original unresolved early offer was superseded.
			call.contextLost = true
		} else {
			next.recoveryEligible = old.dialogConfirmed
			if old.method == "INVITE" && (!old.hasSDP || old.reliableAnswered) && !old.missing {
				answerSide := side
				answerSide.prack = true
				if b.bodylessReliablyAnswered(call, side, old, time.Now()) {
					b.removeDerivation(call, answerSide)
				} else if response := call.derivations[derivationSide{side.peer, side.sender, side.initiator, false}]; !old.dialogConfirmed && response != nil && response.hasSDP && response.cseq == old.cseq {
					// A new UPDATE offer cannot answer the outstanding response.
					next.complete = false
				} else if response != nil && response.hasSDP && response.cseq == old.cseq && !old.hasSDP {
					next.recoveryPending = true
				}
			}
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
	prior.retirementEndpoints = nil
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
func (b *Bridge) acceptDerivation(call *selectedCall, result pipeline.SIPResult) bool {
	if result.ResponseCode < 200 || result.ResponseCode >= 300 || !validRecoveryCSeq(result) || (result.CSeqMethod != "INVITE" && result.CSeqMethod != "UPDATE") {
		return false
	}
	key := b.key(result, nil)
	if _, valid := sideFor(key); !valid {
		return false
	}
	request := call.derivations[derivationSide{key.FromTag, key.ToTag, key.FromTag, false}]
	holdPrevious := request != nil && request.recoveryEligible
	for side, state := range call.derivations {
		if side.prack || state.rejected || side.initiator != key.FromTag || state.cseq != key.CSeq || state.branch != key.Branch || state.method != key.CSeqMethod || (side.peer != key.ToTag && side.sender != key.ToTag) {
			continue
		}
		next := *state
		next.accepted = true
		if !holdPrevious {
			next.previous = nil
		}
		b.putDerivation(call, side, &next)
	}
	return b.finishConfirmedNegotiation(call, key)
}

// A late request may complete an already accepted response. Evidence that the
// dialog was established before this exchange survives the bounded predecessor
// and is distinct from acceptance of the current transaction.
func (b *Bridge) finishConfirmedNegotiation(call *selectedCall, key mediaadmission.DialogKey) bool {
	requestSide := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
	request := call.derivations[requestSide]
	response := call.derivations[derivationSide{key.ToTag, key.FromTag, key.FromTag, false}]
	if !acceptedTransaction(request, key) || !acceptedTransaction(response, key) || request.missing {
		return false
	}
	if key.CSeqMethod == "INVITE" && !request.dialogConfirmed {
		next := *request
		next.dialogConfirmed = true
		if !b.putDerivation(call, requestSide, &next) {
			return false
		}
		request = call.derivations[requestSide]
	}
	if !request.complete || !response.complete || !request.hasSDP || !response.hasSDP || response.missing {
		return false
	}
	replacement := request.recoveryEligible
	answerSide := requestSide
	answerSide.prack = true
	if answer := call.derivations[answerSide]; replacement && answer != nil {
		if answer.cseq >= key.CSeq {
			return false
		}
		b.removeDerivation(call, answerSide)
	}
	for _, side := range []derivationSide{requestSide, {key.ToTag, key.FromTag, key.FromTag, false}} {
		next := *call.derivations[side]
		next.previous = nil
		if replacement {
			next.recoveryPending = false
			next.retirementEndpoints = nil
		}
		if !b.putDerivation(call, side, &next) {
			return false
		}
	}
	return replacement
}

func acceptedTransaction(state *derivationState, key mediaadmission.DialogKey) bool {
	return state != nil && state.accepted && !state.rejected && state.cseq == key.CSeq && state.branch == key.Branch && state.method == key.CSeqMethod
}

func (b *Bridge) requireRequestDerivation(call *selectedCall, result pipeline.SIPResult) {
	key := b.key(result, nil)
	b.bindEarlyDerivation(call, key)
	side := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
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
	if old != nil {
		next.dialogConfirmed, next.recoveryEligible = old.dialogConfirmed, old.dialogConfirmed
		next.recoveryPending = old.recoveryPending
		next.retirementEndpoints = old.retirementEndpoints
		if old.complete && old.hasSDP {
			prior := *old
			prior.previous = nil
			prior.retirementEndpoints = nil
			next.previous = &prior
		}
	}
	b.putDerivation(call, side, next)
}

// Rejected current transactions retain a bounded sequence watermark. Removing
// them entirely would allow a delayed successful response to revive the offer.
func (b *Bridge) rejectDerivation(call *selectedCall, result pipeline.SIPResult) {
	if result.CSeqMethod == "PRACK" && validRecoveryCSeq(result) {
		b.rejectPRACK(call, b.key(result, nil))
		return
	}
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
		if side.prack || side.initiator != result.FromTag || state.cseq != result.CSeqNumber || state.branch != result.ViaBranch || state.method != result.CSeqMethod {
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
			next := &derivationState{cseq: state.cseq, branch: state.branch, method: state.method, complete: true, rejected: true, previous: state.previous, dialogConfirmed: state.dialogConfirmed}
			if !b.retainRetirementEndpoints(call, next, state) {
				return
			}
			b.putDerivation(call, side, next)
		}
		retired = true
	}
	if !retired {
		side := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
		old := call.derivations[side]
		if old != nil && old.cseq >= key.CSeq {
			return
		}
		next := &derivationState{cseq: key.CSeq, branch: key.Branch, method: key.CSeqMethod, complete: true, rejected: true}
		if old != nil {
			next.dialogConfirmed = old.dialogConfirmed
		}
		if old != nil && old.complete && old.hasSDP {
			prior := *old
			prior.previous = nil
			prior.retirementEndpoints = nil
			next.previous = &prior
		}
		b.putDerivation(call, side, next)
	}
	call.known = true
	for side, state := range call.derivations {
		if side.prack && side.initiator == key.FromTag && side.peer == key.ToTag && uint64(state.rackCSeq) == key.CSeq {
			b.removeDerivation(call, side)
		}
	}
}

func (b *Bridge) derivationRejected(call *selectedCall, key mediaadmission.DialogKey) bool {
	for side, state := range call.derivations {
		if !side.prack && state.rejected && side.initiator == key.FromTag && state.cseq == key.CSeq && state.branch == key.Branch && state.method == key.CSeqMethod && (side.peer == "" || side.peer == key.ToTag || side.sender == key.ToTag) {
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
		if side.prack || side.sender != key.FromTag || side.initiator != key.FromTag || side.peer == "" || state.cseq != key.CSeq || state.branch != key.Branch || state.method != key.CSeqMethod {
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
	response := call.derivations[derivationSide{side.peer, side.sender, side.initiator, false}]
	return response != nil && response.responseCode >= 200 && !response.reliable && !response.rejected && response.hasSDP && response.cseq == key.CSeq && response.branch == request.branch && response.method == "INVITE"
}

func (b *Bridge) derivationSummary(call *selectedCall) (bool, bool, map[mediaadmission.EndpointKey]struct{}) {
	known, unknown := call.known, call.contextLost
	media := make(map[mediaadmission.EndpointKey]struct{})
	for side, state := range call.derivations {
		if side.initiator == "" {
			// Independent attribution requirements cannot establish knowledge of
			// an otherwise unobserved offer/answer exchange.
			for _, endpoint := range state.endpoints {
				media[endpoint] = struct{}{}
			}
			continue
		}
		unknown = unknown || state.recoveryPending
		if side.prack {
			// PRACK is an answer only with its exact observed reliable offer.
			known = known || state.hasSDP
			unknown = unknown || !b.reliableAnswerMatches(call, side, state, time.Now())
		}
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
			response := call.derivations[derivationSide{side.peer, side.sender, side.initiator, false}]
			if response != nil && response.hasSDP && !response.rejected && response.cseq == state.cseq {
				unknown = unknown || !b.bodylessReliablyAnswered(call, side, state, time.Now())
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
