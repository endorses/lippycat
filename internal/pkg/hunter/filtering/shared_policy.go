//go:build hunter || all

package filtering

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/grpc"
)

type sharedPolicyConsumer struct {
	lease      capturePolicyLease
	mu         sync.Mutex
	config     filterpolicy.Config
	state      *filterpolicy.State
	supported  map[string]bool
	connection grpc.ClientConnInterface
	pending    *management.SignedPolicySnapshot
	ready      chan struct{}
	readyOnce  sync.Once
}

func (m *Manager) InitializeSharedPolicy(config filterpolicy.Config, supportedTypes []string) error {
	config, err := filterpolicy.Normalize(config)
	if err != nil {
		return err
	}
	if config.Mode != "shared" {
		return nil
	}
	if config.SigningKeyFile != "" || len(config.Replicas) > 0 {
		return fmt.Errorf("hunters cannot sign or replicate authority policy")
	}
	if config.Owner == "li" && config.Startup != "wait" {
		return fmt.Errorf("LI-owned capture requires startup wait for a fresh signed revision")
	}
	state, err := filterpolicy.Open(config)
	if err != nil {
		return err
	}
	policy := &sharedPolicyConsumer{config: config, state: state, supported: make(map[string]bool), ready: make(chan struct{})}
	if len(supportedTypes) == 0 {
		supportedTypes = []string{"bpf", "ip_address"}
	}
	for _, kind := range supportedTypes {
		policy.supported[kind] = true
	}
	m.sharedPolicy = policy
	current := state.Latest()
	if current != nil {
		policy.lease.bootRevision = current.Snapshot.Revision
	}
	if config.Startup == "cached" && current == nil {
		return errors.Join(fmt.Errorf("cached shared-policy startup requires a verified stored snapshot"), m.CloseSharedPolicy())
	}
	if config.Startup == "cached" && current != nil {
		if err := m.installSharedPolicy(current, true); err != nil {
			return errors.Join(err, m.CloseSharedPolicy())
		}
	}
	if config.Startup == "local" {
		policy.readyOnce.Do(func() { close(policy.ready) })
	}
	return nil
}

func (m *Manager) SharedReady() <-chan struct{} {
	if m.sharedPolicy != nil {
		return m.sharedPolicy.ready
	}
	ready := make(chan struct{})
	close(ready)
	return ready
}
func (m *Manager) SharedStartupReady() bool {
	select {
	case <-m.SharedReady():
		return true
	default:
		return false
	}
}
func (m *Manager) CloseSharedPolicy() error {
	if m.sharedPolicy == nil {
		return nil
	}
	return m.sharedPolicy.state.Close()
}

// InitializePolicy is an optional connection setup hook. Unsigned registration
// filters are ignored in shared mode. A changed event policy is staged until
// the ready event transport can drain/rotate its previous producer session.
func (m *Manager) InitializePolicy(ctx context.Context, connection grpc.ClientConnInterface) error {
	policy := m.sharedPolicy
	if policy == nil {
		return nil
	}
	snapshot, err := management.NewFilterPolicyServiceClient(connection).GetSnapshot(ctx, &management.PolicySnapshotRequest{Domain: policy.config.Domain, AuthorityId: policy.config.AuthorityID}, grpc.MaxCallRecvMsgSize(filterpolicy.MaxSnapshotBytes))
	if err != nil {
		return fmt.Errorf("fetch required signed shared policy: %w", err)
	}
	if err := m.checkAndAccountCaptureSnapshot(snapshot); err != nil {
		return err
	}
	if _, err := m.sharedFilters(snapshot.Snapshot); err != nil {
		return err
	}
	policy.mu.Lock()
	defer policy.mu.Unlock()
	policy.connection = connection
	m.capturePolicyConnected()
	m.mu.RLock()
	deferInitial := m.initialApplied && m.policyCoordinator != nil
	m.mu.RUnlock()
	if deferInitial {
		policy.pending = snapshot
		return nil
	}
	return m.installSharedPolicy(snapshot, true)
}

func (m *Manager) sharedFilters(snapshot *management.PolicySnapshot) ([]*management.Filter, error) {
	var result []*management.Filter
	for _, filter := range snapshot.Filters {
		targeted := len(filter.TargetHunters) == 0
		for _, id := range filter.TargetHunters {
			targeted = targeted || id == m.hunterID
		}
		if !targeted {
			continue
		}
		kind := filtercodec.FilterTypeToString(filter.Type)
		if !m.sharedPolicy.supported[kind] {
			if !filter.Enabled {
				continue
			}
			return nil, fmt.Errorf("shared policy targets hunter with unsupported filter type %s", kind)
		}
		result = append(result, filter)
	}
	return result, nil
}

func (m *Manager) installSharedPolicy(snapshot *management.SignedPolicySnapshot, initial bool) error {
	if err := m.checkAndAccountCaptureSnapshot(snapshot); err != nil {
		return err
	}
	_, err := m.sharedFilters(snapshot.Snapshot)
	if err != nil {
		return err
	}
	policy := m.sharedPolicy
	err = policy.state.Accept(snapshot, func(verified *management.PolicySnapshot) error {
		filters, err := m.sharedFilters(verified)
		if err != nil {
			return err
		}
		if policy.config.Owner == "li" {
			return m.installCaptureSnapshot(snapshot, filters)
		}
		if m.sharedSelectionSnapshotRequired(verified) {
			if m.filterValidator != nil {
				if err := m.filterValidator(filters); err != nil {
					return err
				}
			}
			m.mu.RLock()
			coordinator := m.policyCoordinator
			m.mu.RUnlock()
			if coordinator != nil {
				if _, ok := coordinator.(captureSnapshotCoordinator); !ok {
					return errors.New("capture-selection grants require a producer boundary that preserves signed capture proof")
				}
			}
			// The same producer boundary installs matching filters and signed
			// grant evidence. Later ordinary replacements, including version 1
			// withdrawals, must also replace the previously installed evidence.
			return m.installCaptureSnapshot(snapshot, filters)
		}
		if initial {
			return m.setInitialFilters(filters)
		}
		m.applyMu.Lock()
		defer m.applyMu.Unlock()
		return m.replaceSnapshot(filters)
	})
	if err != nil {
		policy.lease.mu.Lock()
		policy.lease.fault = true
		policy.lease.mu.Unlock()
		// Retain the previous matchers for diagnostics but stop packet admission when
		// durable desired policy could not cross its effective installation boundary.
		if !policy.state.Ready() {
			if quiescer, ok := m.captureRestarter.(interface{ Quiesce(context.Context) error }); ok {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				quiesceErr := quiescer.Quiesce(ctx)
				cancel()
				err = errors.Join(err, quiesceErr)
			}
		}
		return err
	}
	policy.readyOnce.Do(func() { close(policy.ready) })
	return nil
}

func (m *Manager) applyPendingSharedPolicy() error {
	policy := m.sharedPolicy
	policy.mu.Lock()
	defer policy.mu.Unlock()
	if policy.pending == nil {
		return nil
	}
	snapshot := policy.pending
	if err := m.installSharedPolicy(snapshot, false); err != nil {
		return err
	}
	policy.pending = nil
	return nil
}

func (m *Manager) subscribeSharedPolicy(ctx, connCtx context.Context) {
	defer m.PolicyDisconnected()
	policy := m.sharedPolicy
	policy.mu.Lock()
	connection := policy.connection
	policy.mu.Unlock()
	if connection == nil {
		m.disconnectMarker.MarkDisconnected()
		return
	}
	m.capturePolicyConnected()
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(connCtx, cancel)
	defer stop()
	stream, err := management.NewFilterPolicyServiceClient(connection).SubscribeSnapshots(streamCtx, &management.PolicySnapshotRequest{Domain: policy.config.Domain, AuthorityId: policy.config.AuthorityID}, grpc.MaxCallRecvMsgSize(filterpolicy.MaxSnapshotBytes))
	if err == nil {
		for {
			snapshot, receiveErr := stream.Recv()
			if receiveErr != nil {
				err = receiveErr
				break
			}
			policy.mu.Lock()
			err = m.installSharedPolicy(snapshot, false)
			policy.mu.Unlock()
			if err != nil {
				break
			}
		}
	}
	if ctx.Err() == nil && connCtx.Err() == nil {
		logger.Error("Shared filter policy subscription failed", "error", err)
		m.disconnectMarker.MarkDisconnected()
	}
}
