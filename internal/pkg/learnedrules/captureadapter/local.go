package captureadapter

import (
	"context"
	"errors"
	"sync"
	"time"

	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
)

// LocalSubscription consumes the same immutable snapshots as the remote control
// service, without a loopback connection or a protocol-mode dependency.
type LocalSubscription struct {
	cancel       context.CancelFunc
	done         chan struct{}
	subscription *core.Subscription
	mu           sync.Mutex
	err          error
}

func StartLocalSubscription(ctx context.Context, runtime *core.Runtime, subscription *core.Subscription) (*LocalSubscription, error) {
	if ctx == nil || runtime == nil || subscription == nil {
		return nil, core.ErrInvalid
	}
	cfg := runtime.Configuration()
	if cfg.HunterID == "" {
		return nil, core.ErrScope
	}
	initial := subscription.Initial
	if !initial.Ready || initial.Session.ProcessorID != cfg.ProcessorID {
		return nil, core.ErrAuthority
	}
	control, err := runtime.Store.StartSession(cfg.ProcessorID, initial.Session)
	if err != nil {
		return nil, err
	}
	apply := func(snapshot core.Snapshot) error {
		if !snapshot.Ready || snapshot.Session != initial.Session {
			return core.ErrSession
		}
		var local []core.Binding
		for _, binding := range snapshot.Rules {
			for _, scope := range binding.Scope {
				if scope.HunterID == cfg.HunterID {
					if !wire.EvidenceRepresentable(binding) {
						return core.ErrUnsupported
					}
					local = append(local, binding)
					break
				}
			}
		}
		return runtime.Store.ApplySnapshot(control, core.Revision(snapshot.Sequence), local)
	}
	if err = apply(initial.Snapshot); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	result := &LocalSubscription{cancel: cancel, done: make(chan struct{}), subscription: subscription}
	go func() {
		defer close(result.done)
		defer subscription.Close()
		interval := cfg.MaxLifetime / 3
		if interval > time.Second {
			interval = time.Second
		}
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer func() {
			_, err := runtime.Store.StartSession(cfg.ProcessorID, initial.Session)
			if err != nil && !errors.Is(err, core.ErrClosed) {
				result.mu.Lock()
				result.err = errors.Join(result.err, err)
				result.mu.Unlock()
			}
		}()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
				if err := runtime.Store.Sweep(); err != nil {
					result.mu.Lock()
					result.err = err
					result.mu.Unlock()
					return
				}
			case change, ok := <-subscription.Events:
				if !ok || change.ResyncRequired {
					result.mu.Lock()
					result.err = core.ErrRevision
					result.mu.Unlock()
					return
				}
				if err := apply(change.Snapshot); err != nil {
					result.mu.Lock()
					result.err = err
					result.mu.Unlock()
					return
				}
			}
		}
	}()
	return result, nil
}

func (s *LocalSubscription) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
