//go:build hunter || all

package hunter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/admissionadapter"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type hunterMediaRules struct {
	store                *mediarules.Store
	settings             mediarules.Settings
	hunterID             string
	domains              mediaadmission.Config
	projection           *admissionadapter.Projection
	mu                   sync.Mutex
	receiver             *wire.Receiver
	capturePolicyCurrent func(uint64) bool
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
		runtime.projection, err = admissionadapter.New(context.Background(), h.config.MediaAdmission.Controller, domainConfig.Domains(), func(err error) { logger.Error("Remote media admission is incomplete", "error", err) })
		if err != nil {
			return err
		}
		observer = runtime.projection
	}
	runtime.store, err = mediarules.New(settings.StoreConfig(settings.ProcessorID, h.config.HunterID, domainConfig.Domains(), observer))
	if err != nil {
		return err
	}
	h.config.MediaRules = settings
	if h.config.FilterPolicy.Owner == "li" {
		runtime.capturePolicyCurrent = func(revision uint64) bool {
			return revision != 0 && h.filterManager != nil && h.filterManager.CaptureAllowed(time.Now()) && h.filterManager.EffectiveCapturePolicyRevision() == revision
		}
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

func mediaRulePacketEndpoints(packet gopacket.Packet, domain mediaadmission.DomainID) (mediaadmission.EndpointKey, mediaadmission.EndpointKey, bool) {
	if packet == nil || packet.NetworkLayer() == nil {
		return mediaadmission.EndpointKey{}, mediaadmission.EndpointKey{}, false
	}
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok {
		return mediaadmission.EndpointKey{}, mediaadmission.EndpointKey{}, false
	}
	source, err := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Src().String())
	if err != nil {
		return mediaadmission.EndpointKey{}, mediaadmission.EndpointKey{}, false
	}
	destination, err := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Dst().String())
	if err != nil {
		return mediaadmission.EndpointKey{}, mediaadmission.EndpointKey{}, false
	}
	left, err := mediaadmission.NewEndpoint(domain, source, uint16(udp.SrcPort))
	if err != nil {
		return left, mediaadmission.EndpointKey{}, false
	}
	right, err := mediaadmission.NewEndpoint(domain, destination, uint16(udp.DstPort))
	return left, right, err == nil
}

func remoteAssociation(call mediarules.CallAssociation, session mediarules.Session) voip.RemoteCallAssociation {
	return voip.RemoteCallAssociation{CallID: call.CallID, Lifetime: call.Lifetime, SelectionRevision: call.SelectionRevision, CapturePolicyRevision: call.CapturePolicyRevision, ProcessorID: session.ProcessorID, ControlGeneration: session.Generation, InheritedFilterIDs: append([]string(nil), call.FilterIDs...)}
}

func (r *hunterMediaRules) ResolveMedia(packet gopacket.Packet, iface string) (voip.RemoteCallAssociation, bool) {
	sequence := r.store.Status().Sequence
	if !r.ready() {
		return voip.RemoteCallAssociation{}, false
	}
	left, right, ok := mediaRulePacketEndpoints(packet, r.domains.DomainForInterface(iface))
	if !ok {
		return voip.RemoteCallAssociation{}, false
	}
	payload := packet.TransportLayer().(*layers.UDP).Payload
	if len(payload) < 8 || payload[0]>>6 != 2 {
		return voip.RemoteCallAssociation{}, false
	}
	rtcp := payload[1] >= 192 && payload[1] <= 223
	if !rtcp && len(payload) < 12 {
		return voip.RemoteCallAssociation{}, false
	}
	resolution := r.store.Resolve(left, right)
	if !resolution.Resolved || r.capturePolicyCurrent != nil && !r.capturePolicyCurrent(resolution.Call.CapturePolicyRevision) {
		return voip.RemoteCallAssociation{}, false
	}
	// Endpoint kind is an independent rule constraint, not just a version-bit
	// signature. Resolve also checks both known endpoint owners intersect.
	for _, rule := range r.store.ActiveRules() {
		if rule.Call.CallID != resolution.Call.CallID || rule.Call.Lifetime != resolution.Call.Lifetime {
			continue
		}
		for _, endpoint := range rule.Endpoints {
			if endpoint.Key != left && endpoint.Key != right {
				continue
			}
			if endpoint.Kind == mediarules.RTPAndRTCP || (rtcp && endpoint.Kind == mediarules.RTCP) || (!rtcp && endpoint.Kind == mediarules.RTP) {
				if r.store.Status().Sequence != sequence || !r.ready() {
					return voip.RemoteCallAssociation{}, false
				}
				return remoteAssociation(rule.Call, rule.Session), true
			}
		}
	}
	return voip.RemoteCallAssociation{}, false
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
	stream, err := client.SubscribeMediaRules(ctx, &management.MediaRuleRequest{ProtocolVersion: wire.Version, HunterId: r.hunterID, ProcessorId: r.settings.ProcessorID}, grpc.MaxCallRecvMsgSize(r.settings.MaxMessageBytes))
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
