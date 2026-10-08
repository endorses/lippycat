//go:build (processor || tap || all) && li

package processor

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/uuid"
)

func (p *Processor) prepareLICorrelation() error {
	config := p.config.LICallCorrelation.Normalized()
	if err := config.Validate(); err != nil {
		return fmt.Errorf("configure LI call correlation: %w", err)
	}
	if !config.Enabled() {
		return nil
	}
	// A stateless manager can reuse task generations after restart. Give its
	// memberships a fresh instance context; persistent managers use their stable
	// authenticated administrative incarnation instead.
	context := uuid.Nil
	if p.liManager != nil {
		context = p.liManager.StateIncarnation()
	}
	if context == uuid.Nil {
		var err error
		context, err = uuid.NewRandom()
		if err != nil {
			return fmt.Errorf("allocate LI correlation task context: %w", err)
		}
	}
	p.liStorage.correlationContext = context
	var store *li.CallCorrelationStore
	if config.StoreFile != "" {
		path, err := filepath.Abs(config.StoreFile)
		if err != nil {
			return fmt.Errorf("resolve LI correlation store: %w", err)
		}
		for _, protected := range []string{p.config.FilterFile, p.config.LIStateFile, p.config.LIRADIUSCorrelationStateFile} {
			if protected == "" {
				continue
			}
			other, err := filepath.Abs(protected)
			if err != nil {
				return fmt.Errorf("resolve protected LI storage: %w", err)
			}
			if path == other {
				return errors.New("LI correlation store must be separate from other stores")
			}
		}
		store, err = li.OpenCallCorrelationStore(path, config.StoreKeys, config.MaxRecords)
		if err != nil {
			return fmt.Errorf("authenticate LI call correlation store: %w", err)
		}
	}
	var persistence li.CallCorrelationPersistence
	if store != nil {
		persistence = store
	}
	correlator, err := li.NewCallCorrelator(config, voip.GetConfig().CallExpirationTime, persistence)
	if err != nil {
		if store != nil {
			err = errors.Join(err, store.Close())
		}
		return err
	}
	p.liStorage.correlation, p.liStorage.correlationStore = correlator, store
	return nil
}

func (p *Processor) liCorrelationKeyring() *securestore.Keyring {
	if p.liStorage == nil || p.liStorage.correlationStore == nil {
		return nil
	}
	return p.liStorage.correlationStore.Keyring()
}

func (p *Processor) publishLICorrelation(decision *li.CallCorrelationDecision) {
	if decision != nil && p.liStorage != nil && p.liStorage.correlation != nil {
		p.liStorage.correlation.Published(*decision)
	}
}

func (p *Processor) startLICorrelationMaintenance() {
	if p.liStorage == nil || p.liStorage.correlation == nil {
		return
	}
	p.liStorage.correlationStop = make(chan struct{})
	p.liStorage.correlationWorkers.Add(1)
	go func() {
		defer p.liStorage.correlationWorkers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var lastWarning time.Time
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-p.liStorage.correlationStop:
				return
			case now := <-ticker.C:
				if err := p.liStorage.correlation.Maintain(); err != nil && (lastWarning.IsZero() || now.Sub(lastWarning) >= time.Minute) {
					// Store errors can include paths. Status supplies aggregate fault
					// state; keep periodic logs free of call identities and key paths.
					logger.Warn("LI call correlation persistence retry failed", "unresolved_writes", p.liStorage.correlation.Stats().UnresolvedWrites)
					lastWarning = now
				}
			}
		}
	}()
}
