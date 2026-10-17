//go:build hunter || all

package filtering

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

type captureSnapshotCoordinator interface {
	ApplyCaptureSnapshot([]byte, func() error) error
}

type capturePolicyLease struct {
	mu           sync.Mutex
	encoded      []byte
	snapshot     *management.PolicySnapshot
	bootRevision uint64
	lastWall     int64
	deadline     time.Time
	connected    bool
	fault        bool
}

func (m *Manager) CapturePolicyStorageKeyring() *securestore.Keyring {
	if m.sharedPolicy == nil {
		return nil
	}
	return m.sharedPolicy.state.Keyring()
}

func (m *Manager) PolicyRevision() uint64 {
	if m.sharedPolicy == nil {
		return 0
	}
	return m.sharedPolicy.state.Revision()
}

func (m *Manager) EffectiveCapturePolicy() []byte {
	if m.sharedPolicy == nil {
		return nil
	}
	lease := &m.sharedPolicy.lease
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fault {
		return nil
	}
	return append([]byte(nil), lease.encoded...)
}

// CaptureAllowed applies only to explicitly selected LI-owned policy. Normal
// local/shared packet capture has no interception lease requirement.
func (m *Manager) CaptureAllowed(now time.Time) bool {
	if m.sharedPolicy == nil || m.sharedPolicy.config.Owner != "li" {
		return true
	}
	lease := &m.sharedPolicy.lease
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.snapshot == nil || lease.fault {
		return false
	}
	wall := now.UnixNano()
	if wall < lease.lastWall {
		lease.fault = true
		return false
	}
	lease.lastWall = wall
	policy := lease.snapshot
	hasApplicableFilter := false
	for _, filter := range policy.Filters {
		if filter == nil || !filter.Enabled {
			continue
		}
		if len(filter.TargetHunters) == 0 {
			hasApplicableFilter = true
			break
		}
		for _, source := range filter.TargetHunters {
			if source == m.hunterID {
				hasApplicableFilter = true
				break
			}
		}
	}
	if !hasApplicableFilter {
		return false
	}
	if wall < policy.ValidFromNs || wall >= policy.ValidUntilNs || !now.Before(lease.deadline) {
		return false
	}
	return lease.connected || policy.AllowOfflineCapture
}

func (m *Manager) PolicyDisconnected() {
	if m.sharedPolicy == nil {
		return
	}
	lease := &m.sharedPolicy.lease
	lease.mu.Lock()
	lease.connected = false
	lease.mu.Unlock()
}

func (m *Manager) checkCaptureSnapshot(snapshot *management.PolicySnapshot, remote bool) error {
	if m.sharedPolicy.config.Owner != "li" {
		return nil
	}
	lease := &m.sharedPolicy.lease
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if snapshot == nil || snapshot.ValidUntilNs <= snapshot.ValidFromNs || snapshot.ValidFromNs <= 0 || len(snapshot.CaptureAuthority) == 0 {
		return errors.New("LI-owned capture policy requires authenticated finite validity and authority")
	}
	if remote && lease.snapshot == nil && snapshot.Revision <= lease.bootRevision {
		return errors.New("LI capture restart requires a fresh authority revision; cached policy cannot renew capture")
	}
	if !remote && lease.snapshot == nil {
		return errors.New("LI-owned capture cannot start from cached/local policy")
	}
	now := time.Now().UnixNano()
	if now < snapshot.ValidFromNs || now >= snapshot.ValidUntilNs {
		return errors.New("LI-owned capture policy is outside its signed validity interval")
	}
	allowed := false
	for _, source := range snapshot.SourceIds {
		allowed = allowed || source == m.hunterID
	}
	if !allowed {
		return fmt.Errorf("LI-owned capture policy excludes this source")
	}
	if lease.fault && lease.snapshot != nil && snapshot.Revision <= lease.snapshot.Revision {
		return errors.New("clock rollback requires a fresh signed capture revision")
	}
	return nil
}

// A verified revocation is policy, not a transport failure. Persist its higher
// watermark and revoke the old offline lease even when this source is excluded.
func (m *Manager) checkAndAccountCaptureSnapshot(signed *management.SignedPolicySnapshot) error {
	if err := m.sharedPolicy.state.Check(signed); err != nil {
		return err
	}
	err := m.checkCaptureSnapshot(signed.Snapshot, true)
	if err == nil || m.sharedPolicy.config.Owner != "li" {
		return err
	}
	accountErr := m.sharedPolicy.state.Accept(signed, func(_ *management.PolicySnapshot) error {
		lease := &m.sharedPolicy.lease
		lease.mu.Lock()
		lease.fault = true
		lease.encoded = nil
		lease.snapshot = proto.Clone(signed.Snapshot).(*management.PolicySnapshot)
		lease.mu.Unlock()
		if capture, ok := m.captureRestarter.(interface{ Quiesce(context.Context) error }); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return capture.Quiesce(ctx)
		}
		return nil
	})
	return errors.Join(err, accountErr)
}

func (m *Manager) installCaptureSnapshot(signed *management.SignedPolicySnapshot, filters []*management.Filter) error {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return err
	}
	apply := func() error {
		m.applyMu.Lock()
		defer m.applyMu.Unlock()
		m.mu.RLock()
		previous := cloneFilters(m.filters)
		updater := m.appFilterUpdater
		m.mu.RUnlock()
		if updater != nil {
			updater.UpdateFilters(filters)
		}
		changed := !filtersEqual(previous, filters)
		if active, ok := m.captureRestarter.(interface{ CaptureActive() bool }); ok {
			changed = changed || !active.CaptureActive()
		}
		if changed {
			if err := m.captureRestarter.Restart(filters); err != nil {
				if updater != nil {
					updater.UpdateFilters(previous)
				}
				return err
			}
		}
		m.mu.Lock()
		m.filters = cloneFilters(filters)
		m.initialApplied = true
		m.mu.Unlock()
		lease := &m.sharedPolicy.lease
		lease.mu.Lock()
		now := time.Now()
		lease.encoded = append([]byte(nil), encoded...)
		lease.snapshot = proto.Clone(signed.Snapshot).(*management.PolicySnapshot)
		lease.lastWall = now.UnixNano()
		lease.deadline = now.Add(time.Duration(signed.Snapshot.ValidUntilNs - now.UnixNano()))
		lease.fault = false
		lease.mu.Unlock()
		return nil
	}
	m.mu.RLock()
	coordinator := m.policyCoordinator
	m.mu.RUnlock()
	if owner, ok := coordinator.(captureSnapshotCoordinator); ok {
		err = owner.ApplyCaptureSnapshot(encoded, apply)
	} else {
		err = apply()
	}
	if err != nil {
		return err
	}
	return nil
}

func (m *Manager) capturePolicyConnected() {
	if m.sharedPolicy == nil {
		return
	}
	lease := &m.sharedPolicy.lease
	lease.mu.Lock()
	lease.connected = true
	lease.mu.Unlock()
}

// QuiesceExpiredPolicy stops device reads while control remains available for a
// fresh signed policy. The producer separately gates every packet immediately.
func (m *Manager) QuiesceExpiredPolicy(ctx context.Context) error {
	if m.CaptureAllowed(time.Now()) {
		return nil
	}
	if capture, ok := m.captureRestarter.(interface{ Quiesce(context.Context) error }); ok {
		return capture.Quiesce(ctx)
	}
	return nil
}
