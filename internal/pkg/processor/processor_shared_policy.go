//go:build processor || tap || all

package processor

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type processorPolicy struct {
	installedRevision   atomic.Uint64
	installedSnapshot   atomic.Pointer[management.PolicySnapshot]
	localAuthorityReady atomic.Bool
	management.UnimplementedFilterPolicyServiceServer
	processor     *Processor
	config        filterpolicy.Config
	state         *filterpolicy.State
	signer        crypto.Signer
	publicationMu sync.Mutex
	ready         chan struct{}
	readyOnce     sync.Once
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

func (p *Processor) initSharedPolicy() error {
	config, err := filterpolicy.Normalize(p.config.FilterPolicy)
	if err != nil {
		return err
	}
	p.config.FilterPolicy = config
	if config.Mode != "shared" {
		return nil
	}
	if !p.config.TLSEnabled || !p.config.TLSClientAuth {
		return fmt.Errorf("shared filter policy requires mutually authenticated TLS")
	}
	state, err := filterpolicy.Open(config)
	if err != nil {
		return err
	}
	runtime := &processorPolicy{processor: p, config: config, state: state, ready: make(chan struct{})}
	p.sharedPolicy = runtime
	if config.SigningKeyFile != "" {
		runtime.signer, err = state.Verifier().ReadSigner(config.SigningKeyFile)
		if err != nil {
			return err
		}
	}
	if config.Owner == "li" && runtime.signer != nil {
		if !p.config.LIHandover.Enabled {
			return fmt.Errorf("LI policy signing requires explicitly enabled LI handover")
		}
		return nil // The local LI manager owns these IDs; RPC mutations are gated.
	}
	return p.filterManager.SetSharedNamespace(config.Namespace())
}

func (p *Processor) startSharedPolicy(ctx context.Context) error {
	runtime := p.sharedPolicy
	if runtime == nil {
		return nil
	}
	current := runtime.state.Latest()
	if current == nil {
		// Existing unsigned local IDs cannot silently become owned by a new authority.
		for _, filter := range p.filterManager.GetAll() {
			if runtime.config.Owner == "li" && runtime.signer != nil {
				break
			}
			if strings.HasPrefix(filter.Id, runtime.config.Namespace()) {
				return fmt.Errorf("unsigned local filter conflicts with shared namespace")
			}
		}
		if runtime.config.Startup == "cached" {
			return fmt.Errorf("cached shared-policy startup requires a verified stored snapshot")
		}
	} else {
		if err := runtime.install(current); err != nil {
			return err
		}
	}
	if runtime.config.Startup == "local" {
		runtime.readyOnce.Do(func() { close(runtime.ready) })
	}
	replicationCtx, cancel := context.WithCancel(ctx)
	runtime.cancel = cancel
	for _, endpoint := range runtime.config.Replicas {
		runtime.wg.Add(1)
		go runtime.replicate(replicationCtx, endpoint)
	}
	return nil
}

func (p *Processor) registerSharedPolicy(registrar grpc.ServiceRegistrar) {
	if p.sharedPolicy != nil {
		management.RegisterFilterPolicyServiceServer(registrar, p.sharedPolicy)
	}
}
func (p *Processor) closeSharedPolicy() error {
	if p.sharedPolicy == nil {
		return nil
	}
	if p.sharedPolicy.cancel != nil {
		p.sharedPolicy.cancel()
	}
	p.sharedPolicy.wg.Wait()
	return p.sharedPolicy.state.Close()
}
func (p *Processor) waitSharedPolicy(ctx context.Context) error {
	if p.sharedPolicy == nil {
		return nil
	}
	select {
	case <-p.sharedPolicy.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *Processor) sharedPolicyAdmissionReady() bool {
	if p.sharedPolicy == nil {
		return true
	}
	if p.sharedPolicy.config.Startup == "local" && !p.sharedPolicy.state.HasSnapshot() {
		return true
	}
	return p.sharedPolicy.state.Ready()
}

func (runtime *processorPolicy) install(snapshot *management.SignedPolicySnapshot) error {
	p := runtime.processor
	p.filterMutationMu.Lock()
	defer p.filterMutationMu.Unlock()
	if err := p.filterMutationReady(); err != nil {
		return err
	}
	namespace := runtime.config.Namespace()
	// Validate local capability before committing the authoritative replacement.
	if validator, ok := p.filterTarget.(interface {
		ValidateFilter(*management.Filter) error
	}); ok {
		for _, filter := range snapshot.GetSnapshot().GetFilters() {
			if err := validator.ValidateFilter(filter); err != nil {
				return err
			}
		}
	}
	err := runtime.state.Accept(snapshot, func(snapshot *management.PolicySnapshot) error {
		if runtime.config.Owner == "li" && runtime.signer != nil {
			return nil
		}
		if err := p.filterManager.ReplaceSharedSnapshot(namespace, snapshot.Filters); err != nil {
			return err
		}
		if p.filterTarget != nil && !p.defaultHunterFilterTarget() {
			target, ok := p.filterTarget.(interface {
				ReplaceSharedSnapshot(string, []*management.Filter) error
			})
			if !ok {
				return fmt.Errorf("local target cannot atomically replace shared policy")
			}
			return target.ReplaceSharedSnapshot(namespace, snapshot.Filters)
		}
		return nil
	})
	if err != nil {
		if !runtime.state.Ready() && securestore.OutcomeOf(err) != securestore.NotCommitted {
			// Desired policy is durable, effective state is not ready. Existing core
			// fault handling stops admission/capture until authenticated reconciliation.
			p.filterReconcileFault = ErrFilterReconciliation
			p.blockFilterProcessing()
		}
		return err
	}
	runtime.readyOnce.Do(func() { close(runtime.ready) })
	runtime.installedSnapshot.Store(proto.Clone(snapshot.GetSnapshot()).(*management.PolicySnapshot))
	runtime.installedRevision.Store(snapshot.GetSnapshot().GetRevision())
	return p.reconcileMediaSelection()
}

// Read the effective installed revision without reentering State's acceptance
// mutex from packet admission or a capture-policy boundary callback.
func (p *Processor) currentCapturePolicyRevision() uint64 {
	if p.sharedPolicy == nil {
		return 0
	}
	return p.sharedPolicy.installedRevision.Load()
}

func verifiedPolicyPeer(ctx context.Context) (*tls.ConnectionState, error) {
	remote, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "verified client certificate required")
	}
	auth, ok := remote.AuthInfo.(credentials.TLSInfo)
	if !ok || len(auth.State.VerifiedChains) == 0 || len(auth.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "verified client certificate required")
	}
	return &auth.State, nil
}
func (runtime *processorPolicy) checkRequest(ctx context.Context, req *management.PolicySnapshotRequest) error {
	if _, err := verifiedPolicyPeer(ctx); err != nil {
		return err
	}
	if req.GetDomain() != runtime.config.Domain || req.GetAuthorityId() != runtime.config.AuthorityID {
		return status.Error(codes.PermissionDenied, "shared policy authority/domain does not match")
	}
	return nil
}
func (runtime *processorPolicy) GetSnapshot(ctx context.Context, req *management.PolicySnapshotRequest) (*management.SignedPolicySnapshot, error) {
	if err := runtime.checkRequest(ctx, req); err != nil {
		return nil, err
	}
	snapshot, err := runtime.state.Snapshot()
	if err != nil {
		return nil, policyStatus(err)
	}
	return snapshot, nil
}
func (runtime *processorPolicy) SubscribeSnapshots(req *management.PolicySnapshotRequest, stream management.FilterPolicyService_SubscribeSnapshotsServer) error {
	if err := runtime.checkRequest(stream.Context(), req); err != nil {
		return err
	}
	channel, err := runtime.state.Subscribe()
	if err != nil {
		return policyStatus(err)
	}
	defer runtime.state.Unsubscribe(channel)
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case snapshot, ok := <-channel:
			if !ok {
				return status.Error(codes.Unavailable, "shared policy owner closed")
			}
			if err := stream.Send(snapshot); err != nil {
				return err
			}
		}
	}
}
func (runtime *processorPolicy) ApplySnapshot(ctx context.Context, snapshot *management.SignedPolicySnapshot) (*management.PolicyReceipt, error) {
	if runtime.config.Owner == "li" && runtime.signer != nil {
		return nil, status.Error(codes.PermissionDenied, "LI authority snapshots are published only from the task lifecycle")
	}
	if _, err := verifiedPolicyPeer(ctx); err != nil {
		return nil, err
	}
	if err := runtime.install(snapshot); err != nil {
		return nil, policyStatus(err)
	}
	return &management.PolicyReceipt{Revision: snapshot.GetSnapshot().GetRevision()}, nil
}
func (runtime *processorPolicy) PublishSnapshot(ctx context.Context, publication *management.PolicyPublication) (*management.SignedPolicySnapshot, error) {
	if runtime.config.Owner == "li" {
		return nil, status.Error(codes.PermissionDenied, "LI capture authority is published only from active LI tasks")
	}
	peerState, err := verifiedPolicyPeer(ctx)
	if err != nil {
		return nil, err
	}
	if runtime.signer == nil {
		return nil, status.Error(codes.FailedPrecondition, "this processor has no configured policy signer")
	}
	// A TLS certificate trusted for transport is not permission to mint policy.
	if !filterpolicy.PublicKeysEqual(peerState.PeerCertificates[0].PublicKey, runtime.state.Verifier().TrustedCertificate().PublicKey) {
		return nil, status.Error(codes.PermissionDenied, "publisher is not the pinned policy authority")
	}
	if publication.GetDomain() != runtime.config.Domain || publication.GetAuthorityId() != runtime.config.AuthorityID {
		return nil, status.Error(codes.PermissionDenied, "shared policy authority/domain does not match")
	}
	runtime.publicationMu.Lock()
	defer runtime.publicationMu.Unlock()
	var revision uint64
	if current := runtime.state.Latest(); current != nil {
		revision = current.Snapshot.Revision
	}
	if publication.ExpectedRevision != revision {
		return nil, status.Error(codes.Aborted, "shared policy revision changed; fetch and reconcile before publishing")
	}
	if revision == ^uint64(0) {
		return nil, status.Error(codes.ResourceExhausted, "shared policy revision exhausted")
	}
	snapshot, err := runtime.state.Verifier().SignSnapshot(runtime.signer, &management.PolicySnapshot{ProtocolVersion: 1, Domain: runtime.config.Domain, AuthorityId: runtime.config.AuthorityID, Revision: revision + 1, Filters: publication.Filters, OwnerKind: publication.OwnerKind, CaptureAuthority: publication.CaptureAuthority, ValidFromNs: publication.ValidFromNs, ValidUntilNs: publication.ValidUntilNs, AllowOfflineCapture: publication.AllowOfflineCapture, SourceIds: publication.SourceIds})
	if err != nil {
		return nil, policyStatus(err)
	}
	if err := runtime.install(snapshot); err != nil {
		return nil, policyStatus(err)
	}
	return snapshot, nil
}
func policyStatus(err error) error {
	switch {
	case errors.Is(err, filterpolicy.ErrRollback):
		return status.Error(codes.FailedPrecondition, "shared policy revision rollback or conflict")
	case errors.Is(err, filterpolicy.ErrInvalid):
		return status.Error(codes.PermissionDenied, "shared policy signature or contract invalid")
	case errors.Is(err, filterpolicy.ErrNotReady):
		return status.Error(codes.Unavailable, "shared policy not reconciled")
	default:
		return status.Error(codes.FailedPrecondition, "shared policy operation failed")
	}
}

func (runtime *processorPolicy) replicate(ctx context.Context, endpoint failover.Endpoint) {
	defer runtime.wg.Done()
	for {
		if err := runtime.replicateOnce(ctx, endpoint); err != nil && ctx.Err() == nil {
			logger.Warn("Shared filter policy replica unavailable", "endpoint", endpoint.Address, "error", err)
		}
		timer := time.NewTimer(runtime.config.SyncInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (runtime *processorPolicy) replicateOnce(ctx context.Context, endpoint failover.Endpoint) error {
	// A cached LI snapshot may contain selectors from the previous distribution
	// setting. Reconcile the current task owner and publish its fresh policy
	// before exporting anything to replicas during startup.
	if runtime.config.Owner == "li" && runtime.signer != nil && !runtime.localAuthorityReady.Load() {
		return nil
	}
	snapshot, err := runtime.state.Snapshot()
	if errors.Is(err, filterpolicy.ErrNotReady) {
		return nil
	}
	if err != nil {
		return err
	}
	creds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{CAFile: runtime.processor.config.TLSCAFile, CertFile: runtime.processor.config.TLSCertFile, KeyFile: runtime.processor.config.TLSKeyFile, ServerNameOverride: endpoint.TLSServerName})
	if err != nil {
		return err
	}
	attemptCtx, cancel := context.WithTimeout(ctx, failover.DefaultConfig().AttemptTimeout)
	defer cancel()
	conn, err := grpc.NewClient(endpoint.Address, grpc.WithTransportCredentials(creds), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(constants.MaxGRPCMessageSize)))
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("Close shared policy replica connection", "error", err)
		}
	}()
	receipt, err := management.NewFilterPolicyServiceClient(conn).ApplySnapshot(attemptCtx, snapshot)
	if err != nil {
		return err
	}
	if receipt.GetRevision() != snapshot.Snapshot.Revision {
		return fmt.Errorf("shared policy replica returned mismatched revision")
	}
	return nil
}
