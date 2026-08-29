//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
)

// hunterRuntimeSpec describes the protocol-specific work surrounding the
// common hunter lifecycle.
type hunterRuntimeSpec struct {
	name          string
	setup         func(context.Context, *hunter.Hunter) (func(), error)
	start         func(context.Context, *hunter.Hunter) error
	shutdownDelay time.Duration
}

func runHunterRuntime(config hunter.Config, spec hunterRuntimeSpec) error {
	h, err := hunter.New(config)
	if err != nil {
		return fmt.Errorf("failed to create hunter: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanupSignals := signals.SetupHandler(ctx, cancel)
	defer cleanupSignals()

	if spec.setup != nil {
		cleanup, err := spec.setup(ctx, h)
		if err != nil {
			return fmt.Errorf("failed to initialize %s hunter: %w", spec.name, err)
		}
		if cleanup != nil {
			defer cleanup()
		}
	}

	start := spec.start
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
		logger.Info("Shutdown signal received, stopping hunter...", "protocol", spec.name)
		if spec.shutdownDelay > 0 {
			time.Sleep(spec.shutdownDelay)
		}
		return nil
	}
}
