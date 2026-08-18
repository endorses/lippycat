//go:build li

package li

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// Defaults for MediaDirectionConfig.
const (
	defaultMediaDirectionTTL           = 10 * time.Minute
	defaultMediaDirectionMaxCalls      = 10000
	defaultMediaDirectionSweepInterval = 60 * time.Second
)

// dialogSide identifies a party of a SIP dialog.
type dialogSide int

const (
	sideUnknown dialogSide = iota
	sideCaller
	sideCallee
)

// MediaDirectionConfig configures a MediaDirectionResolver. Zero values select
// the defaults.
type MediaDirectionConfig struct {
	// TTL is how long per-call media state is retained after the last packet.
	TTL time.Duration

	// MaxCalls bounds the number of concurrently tracked calls. Once reached,
	// new calls are not tracked (their media stays Unknown) rather than growing
	// unboundedly.
	MaxCalls int

	// SweepInterval is how often expired call state is evicted. Negative
	// disables the background sweeper (tests drive sweep() directly).
	SweepInterval time.Duration
}

// MediaDirectionStats reports resolver activity.
type MediaDirectionStats struct {
	// ResolvedFromMedia counts SSRCs whose direction was derived from observed
	// signalling (each SSRC is resolved once, then cached).
	ResolvedFromMedia uint64

	// UnknownRTP counts RTP packets that could not be resolved.
	UnknownRTP uint64

	// CallsDropped counts calls not tracked because MaxCalls was reached.
	CallsDropped uint64

	// CallsTracked is the number of calls currently held in state.
	CallsTracked int
}

// callMediaKey identifies per-call media state. Keyed by XID as well as
// Call-ID because direction is relative to a task's target: two tasks may
// intercept the same call with different targets, and each needs its own
// verdict.
type callMediaKey struct {
	xid    uuid.UUID
	callID string
}

// callMediaState holds what has been learned about one intercepted call.
type callMediaState struct {
	// targetSide records which party of the dialog is the intercept target.
	targetSide dialogSide

	// callerEndpoints / calleeEndpoints are the media endpoints each party
	// advertised in SDP. Endpoints are only ever added, so a re-INVITE cannot
	// invalidate an earlier verdict.
	callerEndpoints map[mediaEndpoint]struct{}
	calleeEndpoints map[mediaEndpoint]struct{}

	// ssrcDir caches the resolved direction per RTP SSRC. This is the mechanism
	// that carries a verdict from the leg where both endpoints are known from
	// SDP to the leg where the far end never appears in any SDP.
	ssrcDir map[uint32]x2x3.PayloadDirection

	lastSeen time.Time
}

// MediaDirectionResolver resolves the ETSI TS 103 221-2 Payload Direction of
// RTP media for identity-based targets (SIP URI, tel URI, NAI, username), which
// carry no per-packet SIP identity of their own.
//
// It learns from the SIP signalling of each intercepted call which media
// endpoints belong to the target, then resolves direction ONCE PER SSRC on the
// leg where both endpoints are known from SDP, and applies that verdict to
// every packet carrying the same SSRC.
//
// Resolving per packet instead would invert access-side legs: the SDP the
// network sees belongs to the media gateway, not the handset behind it, so on
// the gateway→handset leg the target's SDP address is the *source* even though
// the audio is arriving at the target. Requiring both endpoints to be SDP-known
// excludes that leg from resolution, and the SSRC cache supplies its direction.
//
// The resolver never guesses: when the evidence is absent it returns
// x2x3.PayloadDirectionUnknown, as before.
//
// Safe for concurrent use.
type MediaDirectionResolver struct {
	ttl      time.Duration
	maxCalls int

	mu    sync.Mutex
	calls map[callMediaKey]*callMediaState

	resolved     atomic.Uint64
	unknownRTP   atomic.Uint64
	callsDropped atomic.Uint64
	warnedFull   atomic.Bool

	stopOnce sync.Once
	stop     chan struct{}
}

// NewMediaDirectionResolver creates a resolver and starts its eviction sweeper
// (unless cfg.SweepInterval is negative). Call Close to release it.
func NewMediaDirectionResolver(cfg MediaDirectionConfig) *MediaDirectionResolver {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultMediaDirectionTTL
	}
	maxCalls := cfg.MaxCalls
	if maxCalls <= 0 {
		maxCalls = defaultMediaDirectionMaxCalls
	}
	sweep := cfg.SweepInterval
	if sweep == 0 {
		sweep = defaultMediaDirectionSweepInterval
	}

	r := &MediaDirectionResolver{
		ttl:      ttl,
		maxCalls: maxCalls,
		calls:    make(map[callMediaKey]*callMediaState),
		stop:     make(chan struct{}),
	}

	if sweep > 0 {
		go r.sweepLoop(sweep)
	}
	return r
}

// Close stops the eviction sweeper. Safe to call more than once, and on nil.
func (r *MediaDirectionResolver) Close() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stop) })
}

// Stats returns a snapshot of resolver activity.
func (r *MediaDirectionResolver) Stats() MediaDirectionStats {
	if r == nil {
		return MediaDirectionStats{}
	}
	r.mu.Lock()
	tracked := len(r.calls)
	r.mu.Unlock()
	return MediaDirectionStats{
		ResolvedFromMedia: r.resolved.Load(),
		UnknownRTP:        r.unknownRTP.Load(),
		CallsDropped:      r.callsDropped.Load(),
		CallsTracked:      tracked,
	}
}

// PayloadDirection resolves the Payload Direction of a packet for a task's
// single target. It uses the stateless per-packet resolver first (IP/CIDR
// targets, and SIP signalling for identity targets), falling back to learned
// media state for RTP.
func (r *MediaDirectionResolver) PayloadDirection(xid uuid.UUID, target TargetIdentity, pkt *types.PacketDisplay) x2x3.PayloadDirection {
	dir := PayloadDirectionForTarget(target, pkt)
	if dir != x2x3.PayloadDirectionUnknown {
		return dir
	}
	if r == nil || pkt == nil || pkt.VoIPData == nil || !pkt.VoIPData.IsRTP {
		return dir
	}
	if !isSIPIdentityTarget(target.Type) {
		return dir
	}
	return r.directionForRTP(xid, pkt)
}

// ObserveSIP records what a SIP packet reveals about an intercepted call: which
// party is the target, and which media endpoints each party advertised.
//
// Must be called for every SIP packet matched by the task, including for
// X3-only tasks — the direction of the media depends on signalling that is not
// itself delivered.
func (r *MediaDirectionResolver) ObserveSIP(xid uuid.UUID, target TargetIdentity, pkt *types.PacketDisplay) {
	if r == nil || pkt == nil || pkt.VoIPData == nil {
		return
	}
	voip := pkt.VoIPData
	if voip.IsRTP || voip.CallID == "" {
		return
	}
	if !isSIPIdentityTarget(target.Type) {
		// IP/CIDR targets resolve per packet; no state needed.
		return
	}

	side := sipIdentitySide(target, voip)
	endpoints := parseSDPMediaEndpoints(sipMessageBody(pkt))
	if side == sideUnknown && len(endpoints) == 0 {
		return
	}

	now := time.Now()
	key := callMediaKey{xid: xid, callID: voip.CallID}

	r.mu.Lock()
	defer r.mu.Unlock()

	state := r.calls[key]
	if state == nil {
		if len(r.calls) >= r.maxCalls && !r.evictExpiredLocked(now) {
			r.callsDropped.Add(1)
			if r.warnedFull.CompareAndSwap(false, true) {
				logger.Warn("LI media direction state at capacity, new calls will report indeterminate direction",
					"max_calls", r.maxCalls)
			}
			return
		}
		state = &callMediaState{
			callerEndpoints: make(map[mediaEndpoint]struct{}, 2),
			calleeEndpoints: make(map[mediaEndpoint]struct{}, 2),
			ssrcDir:         make(map[uint32]x2x3.PayloadDirection, 2),
		}
		r.calls[key] = state
	}
	state.lastSeen = now

	if side != sideUnknown && state.targetSide == sideUnknown {
		state.targetSide = side
		logger.Debug("LI media direction: target side identified",
			"xid", xid, "target_type", target.Type.String(), "is_caller", side == sideCaller)
	}

	if len(endpoints) == 0 {
		return
	}
	owner := state.sdpOwner(voip, endpoints)
	if owner == sideUnknown {
		logger.Debug("LI media direction: SDP owner not attributable, ignoring endpoints",
			"xid", xid, "method", voip.Method, "status", voip.Status)
		return
	}
	set := state.endpointsFor(owner)
	for _, e := range endpoints {
		if _, exists := set[e]; !exists {
			set[e] = struct{}{}
			logger.Debug("LI media direction: learned media endpoint",
				"xid", xid, "endpoint", e.String(), "is_caller", owner == sideCaller)
		}
	}
}

// directionForRTP resolves an RTP packet from learned call state.
func (r *MediaDirectionResolver) directionForRTP(xid uuid.UUID, pkt *types.PacketDisplay) x2x3.PayloadDirection {
	voip := pkt.VoIPData
	if voip.CallID == "" {
		r.unknownRTP.Add(1)
		return x2x3.PayloadDirectionUnknown
	}

	key := callMediaKey{xid: xid, callID: voip.CallID}

	r.mu.Lock()
	defer r.mu.Unlock()

	state := r.calls[key]
	if state == nil {
		// No signalling observed for this call (RTP-only call, or the task was
		// activated mid-call). Nothing to derive from.
		r.unknownRTP.Add(1)
		return x2x3.PayloadDirectionUnknown
	}
	state.lastSeen = time.Now()

	if dir, ok := state.ssrcDir[voip.SSRC]; ok {
		return dir
	}

	dir := state.resolveEndpoints(pkt)
	if dir == x2x3.PayloadDirectionUnknown {
		r.unknownRTP.Add(1)
		return dir
	}

	state.ssrcDir[voip.SSRC] = dir
	r.resolved.Add(1)
	logger.Debug("LI media direction resolved for SSRC",
		"xid", xid, "ssrc", voip.SSRC,
		"from_target", dir == x2x3.PayloadDirectionFromTarget)
	return dir
}

// resolveEndpoints derives the direction of a packet from the call's known
// media endpoints. Both endpoints must be known and belong to opposite parties;
// anything less is not evidence.
func (s *callMediaState) resolveEndpoints(pkt *types.PacketDisplay) x2x3.PayloadDirection {
	if s.targetSide == sideUnknown {
		return x2x3.PayloadDirectionUnknown
	}
	targetSet, peerSet := s.targetAndPeerEndpoints()
	if len(targetSet) == 0 || len(peerSet) == 0 {
		return x2x3.PayloadDirectionUnknown
	}

	src, dst, ok := packetEndpoints(pkt)
	if !ok {
		return x2x3.PayloadDirectionUnknown
	}

	// Exact endpoint match first; fall back to address-only matching, which
	// tolerates symmetric-RTP/NAT port rewriting. Both stages still require
	// both endpoints to be known.
	if dir := classify(targetSet, peerSet, src, dst, matchExact); dir != x2x3.PayloadDirectionUnknown {
		return dir
	}
	return classify(targetSet, peerSet, src, dst, matchAddrOnly)
}

// classify labels a src→dst pair as from/to the target using the supplied
// endpoint matcher.
func classify(targetSet, peerSet map[mediaEndpoint]struct{}, src, dst mediaEndpoint,
	match func(map[mediaEndpoint]struct{}, mediaEndpoint) bool,
) x2x3.PayloadDirection {
	srcTarget := match(targetSet, src)
	srcPeer := match(peerSet, src)
	dstTarget := match(targetSet, dst)
	dstPeer := match(peerSet, dst)

	switch {
	case srcTarget && !srcPeer && dstPeer && !dstTarget:
		return x2x3.PayloadDirectionFromTarget
	case dstTarget && !dstPeer && srcPeer && !srcTarget:
		return x2x3.PayloadDirectionToTarget
	default:
		return x2x3.PayloadDirectionUnknown
	}
}

// matchExact reports whether an endpoint (address and port) is in the set.
func matchExact(set map[mediaEndpoint]struct{}, e mediaEndpoint) bool {
	_, ok := set[e]
	return ok
}

// matchAddrOnly reports whether any endpoint in the set has the same address,
// ignoring the port.
func matchAddrOnly(set map[mediaEndpoint]struct{}, e mediaEndpoint) bool {
	for known := range set {
		if known.addr == e.addr {
			return true
		}
	}
	return false
}

// targetAndPeerEndpoints returns the target's and the other party's endpoint
// sets, based on which side of the dialog the target is.
func (s *callMediaState) targetAndPeerEndpoints() (target, peer map[mediaEndpoint]struct{}) {
	if s.targetSide == sideCaller {
		return s.callerEndpoints, s.calleeEndpoints
	}
	return s.calleeEndpoints, s.callerEndpoints
}

// endpointsFor returns the endpoint set of one party.
func (s *callMediaState) endpointsFor(side dialogSide) map[mediaEndpoint]struct{} {
	if side == sideCaller {
		return s.callerEndpoints
	}
	return s.calleeEndpoints
}

// sdpOwner determines which party advertised the SDP in a SIP message.
//
//   - The offer in an initial INVITE request (no To-tag) belongs to the caller.
//   - The first answer, in a 1xx/2xx response to INVITE, belongs to the callee.
//   - Anything later (re-INVITE, UPDATE, and their responses, which either party
//     may send) is attributed only when its connection address already belongs
//     to one party, and is otherwise ignored rather than guessed.
func (s *callMediaState) sdpOwner(voip *types.VoIPMetadata, endpoints []mediaEndpoint) dialogSide {
	isResponse := voip.Status > 0
	switch {
	case !isResponse && voip.Method == "INVITE" && voip.ToTag == "":
		return sideCaller
	case isResponse && voip.CSeqMethod == "INVITE" &&
		voip.Status >= 100 && voip.Status < 300 && len(s.calleeEndpoints) == 0:
		return sideCallee
	default:
		return s.attributeByAddr(endpoints)
	}
}

// attributeByAddr attributes endpoints to the party that already owns their
// address. Ambiguous or unknown addresses yield sideUnknown.
func (s *callMediaState) attributeByAddr(endpoints []mediaEndpoint) dialogSide {
	caller, callee := false, false
	for _, e := range endpoints {
		if matchAddrOnly(s.callerEndpoints, e) {
			caller = true
		}
		if matchAddrOnly(s.calleeEndpoints, e) {
			callee = true
		}
	}
	switch {
	case caller && !callee:
		return sideCaller
	case callee && !caller:
		return sideCallee
	default:
		return sideUnknown
	}
}

// sipIdentitySide reports which party of the dialog the target is, from the SIP
// From and To identities. Matching both or neither is not evidence.
func sipIdentitySide(target TargetIdentity, voip *types.VoIPMetadata) dialogSide {
	fromHit := sipIdentityMatches(target, voip.From)
	toHit := sipIdentityMatches(target, voip.To)
	switch {
	case fromHit && !toHit:
		return sideCaller
	case toHit && !fromHit:
		return sideCallee
	default:
		return sideUnknown
	}
}

// isSIPIdentityTarget reports whether a target type is matched against SIP
// identities (as opposed to packet addresses).
func isSIPIdentityTarget(t TargetType) bool {
	switch t {
	case TargetTypeSIPURI, TargetTypeTELURI, TargetTypeNAI, TargetTypeUsername:
		return true
	default:
		return false
	}
}

// sweepLoop evicts expired call state periodically.
func (r *MediaDirectionResolver) sweepLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.sweep(time.Now())
		}
	}
}

// sweep removes call state idle for longer than the TTL.
func (r *MediaDirectionResolver) sweep(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evictExpiredLockedCount(now)
}

// evictExpiredLocked evicts expired call state, reporting whether it freed any
// room. Caller must hold r.mu.
func (r *MediaDirectionResolver) evictExpiredLocked(now time.Time) bool {
	return r.evictExpiredLockedCount(now) > 0
}

// evictExpiredLockedCount evicts expired call state and returns how many
// entries were removed. Caller must hold r.mu.
func (r *MediaDirectionResolver) evictExpiredLockedCount(now time.Time) int {
	removed := 0
	for key, state := range r.calls {
		if now.Sub(state.lastSeen) > r.ttl {
			delete(r.calls, key)
			removed++
		}
	}
	if removed > 0 {
		r.warnedFull.Store(false)
		logger.Debug("LI media direction state evicted", "calls", removed)
	}
	return removed
}
