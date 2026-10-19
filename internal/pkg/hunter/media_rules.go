//go:build hunter || all

package hunter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	learnedpb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/admissionadapter"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
	"github.com/google/gopacket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type hunterMediaRules struct {
	store                   *mediarules.Store
	runtime                 *core.Runtime
	genericReceiver         *learnedwire.Receiver
	settings                mediarules.Settings
	hunterID                string
	domains                 mediaadmission.Config
	projection              *admissionadapter.Projection
	mu                      sync.Mutex
	receiver                *wire.Receiver
	capturePolicyCurrent    func(uint64) bool
	captureMediaRuleAllowed func(*management.MediaRule, gopacket.Packet, uint32, time.Time) bool
}

func (h *Hunter) configureMediaRules() error {
	if !h.config.VoIPMode && (h.config.MediaRules.Enabled || h.config.VoIPMediaPolicy == string(voip.MediaProcessor)) {
		return errors.New("temporary media rules require VoIP capture mode")
	}
	if !h.config.VoIPMode {
		return nil
	}
	policies, err := (voip.CapturePolicies{Signalling: voip.SignallingPolicy(h.config.VoIPSignallingPolicy), Media: voip.MediaPolicy(h.config.VoIPMediaPolicy)}).Normalize()
	if err != nil {
		return err
	}
	h.config.VoIPSignallingPolicy, h.config.VoIPMediaPolicy = string(policies.Signalling), string(policies.Media)
	if policies.Media == voip.MediaProcessor {
		h.config.MediaRules.Enabled = true
	}
	if !h.config.MediaRules.Enabled {
		return nil
	}
	if policies.Media != voip.MediaProcessor {
		return errors.New("temporary media rules require media-policy processor")
	}
	settings, err := h.config.MediaRules.Normalize()
	if err != nil {
		return err
	}
	if settings.ProcessorID == "" {
		return errors.New("processor media requires hunter.voip.media_rules.processor_id")
	}
	if !h.config.TLSEnabled || h.config.TLSSkipVerify || h.config.TLSCertFile == "" || h.config.TLSKeyFile == "" {
		return errors.New("processor media requires verified mutual TLS")
	}
	domainConfig := mediaadmission.DefaultConfig()
	domainConfig.InterfaceDomains = h.config.VoIPInterfaceDomains
	if h.config.MediaAdmission != nil {
		domainConfig = h.config.MediaAdmission.Config
		for iface, domain := range h.config.VoIPInterfaceDomains {
			if domainConfig.DomainForInterface(iface) != domain {
				return fmt.Errorf("VoIP interface domain for %s conflicts with RTP admission domain", iface)
			}
		}
	}
	runtime := &hunterMediaRules{settings: settings, hunterID: h.config.HunterID, domains: domainConfig}
	var observer mediarules.Observer
	if h.config.MediaAdmission != nil {
		runtime.projection, err = admissionadapter.NewForSource(context.Background(), h.config.MediaAdmission.Controller, h.config.HunterID, domainConfig.Domains(), func(err error) { logger.Error("Remote media admission is incomplete", "error", err) })
		if err != nil {
			return err
		}
		observer = runtime.projection
	}
	legacyConfig := settings.StoreConfig(settings.ProcessorID, h.config.HunterID, domainConfig.Domains(), observer)
	engineConfig, err := mediarules.EngineConfig(legacyConfig, h.config.LearnedAdapters...)
	engineConfig.SupportedProtocols = []core.Protocol{core.UDP}
	if err != nil {
		return err
	}
	interfaces := make(map[string]core.DomainID)
	for iface, domain := range domainConfig.InterfaceDomains {
		interfaces[iface] = core.DomainID(domain)
	}
	for _, iface := range h.config.Interfaces {
		interfaces[iface] = core.DomainID(domainConfig.DomainForInterface(iface))
	}
	if len(interfaces) == 0 {
		interfaces["any"] = 0
	}
	runtime.runtime, err = core.NewRuntime(engineConfig, interfaces, min(settings.MaxRules, learnedwire.DefaultEvidenceLimits.MaxCandidates), nil)
	if err == nil {
		runtime.store = mediarules.Wrap(runtime.runtime.Store, legacyConfig)
	}
	if err != nil {
		return err
	}
	h.config.MediaRules = settings
	if h.config.FilterPolicy.Owner == "li" {
		runtime.capturePolicyCurrent = func(revision uint64) bool {
			return revision != 0 && h.filterManager != nil && h.filterManager.CaptureAllowed(time.Now()) && h.filterManager.EffectiveCapturePolicyRevision() == revision
		}
	}
	runtime.captureMediaRuleAllowed = func(rule *management.MediaRule, packet gopacket.Packet, domain uint32, at time.Time) bool {
		return h.filterManager != nil && h.filterManager.CaptureMediaRuleAllowed(rule, packet, domain, at)
	}
	h.mediaRules = runtime
	return nil
}

// VoIPMediaResolver returns an instance-owned proxy before capture starts. It is
// fail closed until an authenticated complete snapshot has been applied.
func (h *Hunter) VoIPMediaResolver() voip.RemoteMediaResolver {
	if h.mediaRules == nil {
		return nil
	}
	return h.mediaRules
}

func (r *hunterMediaRules) ready() bool {
	state := r.store.Status()
	return state.Ready
}

func remoteAssociation(call mediarules.CallAssociation, session mediarules.Session) voip.RemoteCallAssociation {
	return voip.RemoteCallAssociation{CallID: call.CallID, Lifetime: call.Lifetime, SelectionRevision: call.SelectionRevision, CapturePolicyRevision: call.CapturePolicyRevision, ProcessorID: session.ProcessorID, ControlGeneration: session.Generation, InheritedFilterIDs: append([]string(nil), call.FilterIDs...)}
}

func (r *hunterMediaRules) ResolveMedia(packet gopacket.Packet, iface string) (voip.RemoteCallAssociation, bool) {
	sequence := r.store.Status().Sequence
	if !r.ready() {
		return voip.RemoteCallAssociation{}, false
	}
	domain := r.domains.DomainForInterface(iface)
	facts, ok := core.PacketFacts(packet, core.DomainID(domain))
	if !ok {
		return voip.RemoteCallAssociation{}, false
	}
	resolution := voiprules.ResolvePacket(r.store.Core(), facts, min(max(1, r.settings.MaxRules), learnedwire.DefaultEvidenceLimits.MaxCandidates))
	if !resolution.Resolved || resolution.Rule == nil || r.capturePolicyCurrent != nil && !r.capturePolicyCurrent(resolution.Call.CapturePolicyRevision) {
		return voip.RemoteCallAssociation{}, false
	}
	rule := resolution.Rule
	association := remoteAssociation(rule.Call, rule.Session)
	if len(rule.Call.SelectionGrants) > 0 {
		encoded := wire.EncodeRule(*rule)
		if r.captureMediaRuleAllowed == nil || !r.captureMediaRuleAllowed(encoded, packet, uint32(domain), time.Now()) {
			return voip.RemoteCallAssociation{}, false
		}
		proof, err := (proto.MarshalOptions{Deterministic: true}).Marshal(encoded)
		if err != nil {
			return voip.RemoteCallAssociation{}, false
		}
		association.CaptureSelectionProof = proof
		for _, ref := range rule.Call.SelectionGrants {
			association.InheritedFilterIDs = append(association.InheritedFilterIDs, ref.ID)
		}
	}
	if r.store.Status().Sequence != sequence || !r.ready() {
		return voip.RemoteCallAssociation{}, false
	}
	return association, true
}

func (r *hunterMediaRules) ResolveSignalling(event sharedsip.Event, packet gopacket.Packet, iface string) (voip.RemoteCallAssociation, bool) {
	sequence := r.store.Status().Sequence
	if !r.ready() || event.CallID == "" || event.FromTag == "" || event.ToTag == "" || event.CSeqMethod == "" || packet == nil || packet.NetworkLayer() == nil {
		return voip.RemoteCallAssociation{}, false
	}
	if event.Method != "RESPONSE" && event.Method != event.CSeqMethod {
		return voip.RemoteCallAssociation{}, false
	}
	domain := r.domains.DomainForInterface(iface)
	resolution := r.store.ResolveDialogInDomain(domain, event.CallID, event.FromTag, event.ToTag)
	if !resolution.Resolved || r.capturePolicyCurrent != nil && !r.capturePolicyCurrent(resolution.Call.CapturePolicyRevision) || r.store.Status().Sequence != sequence || !r.ready() {
		return voip.RemoteCallAssociation{}, false
	}
	return remoteAssociation(resolution.Call, r.store.Status().Session), true
}

// verifiedMediaIssuer binds the configured logical issuer to the already
// chain-verified TLS leaf's DNS/IP SAN. Wire claims and legacy CNs are not trust.
func verifiedMediaIssuer(remote *peer.Peer, expected string) error {
	if remote == nil || expected == "" {
		return mediarules.ErrAuthority
	}
	info, ok := remote.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.PeerCertificates) == 0 {
		return mediarules.ErrAuthority
	}
	if err := info.State.PeerCertificates[0].VerifyHostname(expected); err != nil {
		return fmt.Errorf("media-rule processor identity: %w", err)
	}
	return nil
}

func (r *hunterMediaRules) invalidate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.receiver = nil
	r.genericReceiver = nil
	known := r.store.Status().Session
	if known.Generation == 0 {
		return nil
	}
	_, err := r.store.StartSession(r.settings.ProcessorID, known)
	return err
}

func (r *hunterMediaRules) application() *management.MediaRuleApplication {
	state := r.store.Status()
	active := r.store.ActiveRules()
	endpoints := 0
	for _, rule := range active {
		endpoints += len(rule.Endpoints)
	}
	result := &management.MediaRuleApplication{HunterId: r.hunterID, Session: wire.EncodeSession(state.Session), AppliedRevision: uint64(state.Revision), Synchronized: state.Ready && (r.projection == nil || r.projection.Ready(state.Sequence)), ActiveRules: uint32(len(active)), ActiveEndpoints: uint32(endpoints)}
	if r.projection != nil && r.projection.Error() != nil {
		result.Error = "remote media admission projection is incomplete"
	}
	return result
}

func (r *hunterMediaRules) open(lifetime, setup context.Context, conn grpc.ClientConnInterface) (func() error, error) {
	run, err := r.openGeneric(lifetime, setup, conn)
	if err == nil {
		return run, nil
	}
	adapters := r.store.Core().Configuration().Registry.Adapters()
	exactlyVoIP := len(adapters) == 1 && adapters[0].ID == voiprules.AdapterID && adapters[0].Version == voiprules.ContextVersion
	if !learnedwire.LegacyFallbackAllowed(err, exactlyVoIP) {
		return nil, err
	}
	return r.openLegacy(lifetime, setup, conn)
}

func (r *hunterMediaRules) openLegacy(lifetime, setup context.Context, conn grpc.ClientConnInterface) (func() error, error) {
	if err := r.invalidate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(lifetime)
	stopSetup := context.AfterFunc(setup, cancel)
	completed := false
	defer func() {
		stopSetup()
		if !completed {
			cancel()
			if err := r.invalidate(); err != nil {
				logger.Error("Invalidate failed media-rule setup", "error", err)
			}
		}
	}()
	client := management.NewMediaControlServiceClient(conn)
	stream, err := client.SubscribeMediaRules(ctx, &management.MediaRuleRequest{ProtocolVersion: wire.GrantVersion, HunterId: r.hunterID, ProcessorId: r.settings.ProcessorID}, grpc.MaxCallRecvMsgSize(r.settings.MaxMessageBytes))
	if err != nil {
		return nil, err
	}
	first, err := stream.Recv()
	// Ordinary capture can use legacy media control. Explicit LI-owned capture
	// requires the grant-capable contract and never retries with private filters.
	if err != nil && r.capturePolicyCurrent == nil && legacyMediaVersionUnsupported(err) {
		stream, err = client.SubscribeMediaRules(ctx, &management.MediaRuleRequest{ProtocolVersion: wire.Version, HunterId: r.hunterID, ProcessorId: r.settings.ProcessorID}, grpc.MaxCallRecvMsgSize(r.settings.MaxMessageBytes))
		if err == nil {
			first, err = stream.Recv()
		}
	}
	if err != nil {
		return nil, err
	}
	remote, _ := peer.FromContext(stream.Context())
	if err := verifiedMediaIssuer(remote, r.settings.ProcessorID); err != nil {
		return nil, err
	}
	receiver, err := wire.NewReceiver(r.store, r.settings.ProcessorID, wire.Limits{MaxMessageBytes: r.settings.MaxMessageBytes, MaxSnapshotBytes: r.settings.MaxSnapshotBytes, MaxRules: r.settings.MaxRules})
	if err != nil {
		return nil, err
	}
	for {
		if err := receiver.Apply(first); err != nil {
			return nil, err
		}
		if r.store.Status().Ready {
			break
		}
		first, err = stream.Recv()
		if err != nil {
			return nil, err
		}
	}
	if err := setup.Err(); err != nil {
		return nil, err
	}
	if err := r.report(setup, client); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.receiver = receiver
	r.mu.Unlock()
	completed = true
	return func() error {
		defer cancel()
		for {
			update, err := stream.Recv()
			if err != nil {
				return err
			}
			r.mu.Lock()
			current := r.receiver == receiver
			r.mu.Unlock()
			if !current {
				return mediarules.ErrSession
			}
			if err := receiver.Apply(update); err != nil {
				if invalidateErr := r.invalidate(); invalidateErr != nil {
					return errors.Join(err, invalidateErr)
				}
				return err
			}
			reportCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			err = r.report(reportCtx, client)
			stop()
			if err != nil {
				return err
			}
		}
	}, nil
}

// Legacy v1 servers used this exact status for an unsupported protocol
// version. Arbitrary InvalidArgument errors may describe malformed data and
// never authorize downgrade. Grant-required capture never calls this fallback.
func legacyMediaVersionUnsupported(err error) bool {
	return status.Code(err) == codes.Unimplemented || status.Code(err) == codes.InvalidArgument && status.Convert(err).Message() == "unsupported media-rule subscription"
}

func (r *hunterMediaRules) report(ctx context.Context, client management.MediaControlServiceClient) error {
	receipt, err := client.ReportMediaRuleStatus(ctx, r.application())
	if err != nil {
		return err
	}
	if receipt == nil || !receipt.Accepted {
		return errors.New("processor rejected scoped media-rule application status")
	}
	return nil
}

func (h *Hunter) openMediaRules(lifetime, setup context.Context, conn grpc.ClientConnInterface) (func() error, error) {
	if h.mediaRules == nil {
		return nil, nil
	}
	return h.mediaRules.open(lifetime, setup, conn)
}

func (h *Hunter) maintainMediaRules() {
	if h.mediaRules == nil {
		return
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		interval := min(time.Second, h.mediaRules.settings.RuleTTL/2)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
		timer := time.NewTicker(interval)
		defer timer.Stop()
		for {
			select {
			case <-h.ctx.Done():
				return
			case <-timer.C:
			}
			if err := h.mediaRules.store.Sweep(); err != nil {
				logger.Error("Sweep temporary media rules", "error", err)
				return
			}
			if h.mediaRules.projection != nil && h.mediaRules.projection.Error() != nil {
				if err := h.mediaRules.projection.Retry(); err != nil {
					logger.Debug("Remote media admission retry remains incomplete", "error", err)
				}
			}
		}
	}()
}

func validateProcessorMediaFilters(filters []*management.Filter) error {
	for _, filter := range filters {
		if filter != nil && filter.Enabled && filter.Type == management.FilterType_FILTER_IP_ADDRESS {
			return fmt.Errorf("processor media selection rejects independent IP/CIDR selector %q", filter.Id)
		}
	}
	return nil
}

var _ voip.RemoteMediaResolver = (*hunterMediaRules)(nil)

func (r *hunterMediaRules) ValidateMediaProof(packet gopacket.Packet, iface string, proof []byte, at time.Time) bool {
	if r.captureMediaRuleAllowed == nil || len(proof) == 0 || len(proof) > filterpolicy.MaxMediaRuleBytes {
		return false
	}
	rule := &management.MediaRule{}
	return proto.Unmarshal(proof, rule) == nil && r.captureMediaRuleAllowed(rule, packet, uint32(r.domains.DomainForInterface(iface)), at)
}

func voipLearnedCapabilities() []*learnedpb.LearnedCapability {
	return []*learnedpb.LearnedCapability{learnedCapabilities(voiprules.Adapter())}
}
func learnedCapabilities(adapter core.Adapter) *learnedpb.LearnedCapability {
	capability := &learnedpb.LearnedCapability{SupportedProtocols: []uint32{uint32(core.TCP), uint32(core.UDP)}, AdapterId: adapter.ID, ContextVersion: adapter.Version, EndpointSelectorVersions: []uint32{learnedwire.EndpointSelectorVersion}, EvidenceVersions: []uint32{learnedwire.EvidenceVersion}}
	if adapter.ID == voiprules.AdapterID {
		capability.SupportedProtocols = []uint32{uint32(core.UDP)}
	}
	for _, q := range adapter.Qualifiers {
		capability.Qualifiers = append(capability.Qualifiers, &learnedpb.LearnedQualifier{Id: q.ID, Version: q.Version})
	}
	return capability
}

func (r *hunterMediaRules) openGeneric(lifetime, setup context.Context, conn grpc.ClientConnInterface) (func() error, error) {
	if err := r.invalidate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(lifetime)
	stopSetup := context.AfterFunc(setup, cancel)
	completed := false
	defer func() {
		stopSetup()
		if !completed {
			cancel()
			if err := r.invalidate(); err != nil {
				logger.Error("Invalidate failed learned-rule setup", "error", err)
			}
		}
	}()
	client := learnedpb.NewLearnedControlServiceClient(conn)
	var caps []*learnedpb.LearnedCapability
	for _, adapter := range r.store.Core().Configuration().Registry.Adapters() {
		capability := learnedCapabilities(adapter)
		if supported := r.store.Core().Configuration().SupportedProtocols; len(supported) > 0 {
			capability.SupportedProtocols = nil
			for _, protocol := range supported {
				if adapter.ID != voiprules.AdapterID || protocol == core.UDP {
					capability.SupportedProtocols = append(capability.SupportedProtocols, uint32(protocol))
				}
			}
		}
		caps = append(caps, capability)
	}
	stream, err := client.SubscribeLearnedRules(ctx, &learnedpb.LearnedRuleRequest{ProtocolVersion: learnedwire.Version, HunterId: r.hunterID, ProcessorId: r.settings.ProcessorID, Capabilities: caps}, grpc.MaxCallRecvMsgSize(r.settings.MaxMessageBytes))
	if err != nil {
		return nil, err
	}
	first, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	remote, _ := peer.FromContext(stream.Context())
	if err := verifiedMediaIssuer(remote, r.settings.ProcessorID); err != nil {
		return nil, err
	}
	receiver, err := learnedwire.NewReceiver(r.store.Core(), r.settings.ProcessorID, learnedwire.Limits{MaxMessageBytes: r.settings.MaxMessageBytes, MaxSnapshotBytes: r.settings.MaxSnapshotBytes, MaxRules: r.settings.MaxRules}, caps)
	if err != nil {
		return nil, err
	}
	for {
		if err := receiver.Apply(first); err != nil {
			return nil, err
		}
		if r.store.Status().Ready {
			break
		}
		first, err = stream.Recv()
		if err != nil {
			return nil, err
		}
	}
	if err := setup.Err(); err != nil {
		return nil, err
	}
	if err := r.reportGeneric(setup, client, receiver.SubscriptionID()); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.genericReceiver = receiver
	r.mu.Unlock()
	completed = true
	return func() error {
		defer cancel()
		for {
			update, err := stream.Recv()
			if err != nil {
				return err
			}
			r.mu.Lock()
			current := r.genericReceiver == receiver
			r.mu.Unlock()
			if !current {
				return mediarules.ErrSession
			}
			if err := receiver.Apply(update); err != nil {
				return errors.Join(err, r.invalidate())
			}
			reportCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			err = r.reportGeneric(reportCtx, client, receiver.SubscriptionID())
			stop()
			if err != nil {
				return err
			}
		}
	}, nil
}
func (r *hunterMediaRules) reportGeneric(ctx context.Context, client learnedpb.LearnedControlServiceClient, subscriptionID string) error {
	legacy := r.application()
	application := &learnedpb.LearnedRuleApplication{HunterId: r.hunterID, SubscriptionId: subscriptionID, Session: learnedwire.EncodeSession(r.store.Status().Session), AppliedRevision: legacy.AppliedRevision, Synchronized: legacy.Synchronized, Error: legacy.Error}
	populateLearnedApplication(application, r.store.Core())
	receipt, err := client.ReportLearnedRuleStatus(ctx, application)
	if err != nil {
		return err
	}
	if receipt == nil || !receipt.Accepted {
		return errors.New("processor rejected scoped learned-rule application status")
	}
	return nil
}

// learnedApplicationCounts uses only bounded registered adapter metadata. Source
// scope is checked without altering immutable binding definitions.
func learnedApplicationCounts(store *core.Store) []*learnedpb.LearnedAdapterApplication {
	adapters := store.Configuration().Registry.Adapters()
	bindings := store.ActiveRules()
	result := make([]*learnedpb.LearnedAdapterApplication, 0, len(adapters))
	for _, adapter := range adapters {
		counts := &learnedpb.LearnedAdapterApplication{AdapterId: adapter.ID, ContextVersion: adapter.Version}
		for _, binding := range bindings {
			if binding.AdapterID != adapter.ID || binding.ContextVersion != adapter.Version {
				continue
			}
			counts.ActiveBindings++
			for _, selector := range binding.Selectors {
				if store.InScope(binding, selector.Domain) {
					counts.ActiveSelectors++
				}
			}
		}
		result = append(result, counts)
	}
	return result
}

func populateLearnedApplication(application *learnedpb.LearnedRuleApplication, store *core.Store) {
	state := store.Status()
	application.CandidateOverflows = state.CandidateOverflows
	application.RetainedBytes = uint64(state.Bytes)
	application.Expired = state.Expired
	application.StaleUpdates = state.StaleUpdates
	application.Resyncs = state.Resyncs
	application.CapacityRejections = state.CapacityRejections
	application.AdapterApplications = learnedApplicationCounts(store)
	application.ActiveBindings, application.ActiveSelectors = 0, 0
	for _, counts := range application.AdapterApplications {
		application.ActiveBindings += counts.ActiveBindings
		application.ActiveSelectors += counts.ActiveSelectors
	}
}
