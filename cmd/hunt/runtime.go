//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/pkg/signals"
)

// hunterRuntimeHooks describes analyzer setup surrounding the common hunter
// lifecycle. Protocol identity and capabilities come only from the catalog.
type hunterRuntimeHooks struct {
	setup         func(context.Context, *hunter.Hunter) (func(), error)
	start         func(context.Context, *hunter.Hunter) error
	shutdownDelay time.Duration
}

func runHunterRuntime(config hunter.Config, protocol protocolcatalog.Spec, hooks hunterRuntimeHooks) error {
	if protocol.Name == "" || protocol.Analyzer == "" {
		return fmt.Errorf("protocol catalog specification is incomplete")
	}
	h, err := hunter.New(config)
	if err != nil {
		return fmt.Errorf("failed to create hunter: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanupSignals := signals.SetupHandler(ctx, cancel)
	defer cleanupSignals()

	if hooks.setup != nil {
		cleanup, err := hooks.setup(ctx, h)
		if err != nil {
			return fmt.Errorf("failed to initialize %s hunter: %w", protocol.Name, err)
		}
		if cleanup != nil {
			defer cleanup()
		}
	}

	start := hooks.start
	if start == nil {
		start = func(ctx context.Context, h *hunter.Hunter) error { return h.Start(ctx) }
	}
	errChan := make(chan error, constants.ErrorChannelBuffer)
	go func() {
		if err := start(ctx, h); err != nil {
			errChan <- err
		}
	}()

	select {
	case err := <-errChan:
		return fmt.Errorf("hunter error: %w", err)
	case <-ctx.Done():
		logger.Info("Shutdown signal received, stopping hunter...", "protocol", protocol.Name)
		if hooks.shutdownDelay > 0 {
			time.Sleep(hooks.shutdownDelay)
		}
		return nil
	}
}

func runCatalogHunterRuntime(config hunter.Config, name string, hooks hunterRuntimeHooks) error {
	return runHunterRuntime(config, protocolcatalog.MustLookup(name), hooks)
}
