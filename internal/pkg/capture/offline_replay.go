package capture

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
)

// OfflineReplayOptions controls repeated passes over timestamp-ordered files.
// Set Count to 1 for the usual single pass, or 0 to repeat until cancelled.
// Hooks execute serially; AfterPass runs only after a successful, drained pass.
type OfflineReplayOptions struct {
	Count      int
	Delay      time.Duration
	BeforePass func(pass uint64) error
	AfterPass  func(pass uint64) error
}

// ErrOfflineReplayEmpty prevents continuous replay from spinning over empty or
// fully filtered input. Finite replay can successfully process empty input.
var ErrOfflineReplayEmpty = errors.New("continuous offline replay produced no matching packets")

// RunOfflineOrderedRepeated reopens every source for each ordered pass. The
// consumer is called once per pass; its owner can keep output sinks open for the
// entire replay session and reset analysis or timing state in the pass hooks.
func RunOfflineOrderedRepeated(ctx context.Context, devices []pcaptypes.PcapInterface, filter string,
	options OfflineReplayOptions, consumer func(context.Context, <-chan PacketInfo) error) error {
	if options.Count < 0 {
		return errors.New("offline replay count must be non-negative")
	}
	if options.Delay < 0 {
		return errors.New("offline replay delay must be non-negative")
	}
	if consumer == nil {
		return errors.New("offline replay consumer is required")
	}
	for pass := uint64(1); ; pass++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if options.BeforePass != nil {
			if err := options.BeforePass(pass); err != nil {
				return fmt.Errorf("prepare offline replay pass %d: %w", pass, err)
			}
		}
		var delivered uint64
		if err := runOfflineOrderedStream(ctx, devices, filter, consumer, &delivered); err != nil {
			return fmt.Errorf("offline replay pass %d: %w", pass, err)
		}
		if options.AfterPass != nil {
			if err := options.AfterPass(pass); err != nil {
				return fmt.Errorf("finish offline replay pass %d: %w", pass, err)
			}
		}
		if options.Count == 0 && delivered == 0 {
			return ErrOfflineReplayEmpty
		}
		if options.Count > 0 && pass == uint64(options.Count) {
			return nil
		}
		if options.Delay > 0 {
			timer := time.NewTimer(options.Delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}
