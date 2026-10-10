//go:build cli || all

package sniff

import (
	"context"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func sniffReplayOptions() capture.OfflineReplayOptions {
	count := 1
	if viper.IsSet("sniff.replay_loop") {
		count = viper.GetInt("sniff.replay_loop")
	}
	return capture.OfflineReplayOptions{Count: count, Delay: viper.GetDuration("sniff.replay_loop_delay")}
}

func validateReplayOptions(cmd *cobra.Command, args []string) error {
	opts := sniffReplayOptions()
	if opts.Count < 0 {
		return fmt.Errorf("--replay-loop must be non-negative (0 means continuous)")
	}
	if opts.Delay < 0 {
		return fmt.Errorf("--replay-loop-delay must be non-negative")
	}
	if len(collectReadFiles(readFile, args)) == 0 && (opts.Count != 1 || opts.Delay != 0) {
		return fmt.Errorf("replay loop options require PCAP input files")
	}
	return nil
}

func offlineReplayContext(cmd *cobra.Command) (context.Context, func()) {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	stop := signals.SetupHandler(ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

// A joined cleanup or read error must survive a concurrent user interrupt.
func onlyReplayCancellation(err error) bool {
	if err == context.Canceled {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !onlyReplayCancellation(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyReplayCancellation(wrapped.Unwrap())
	}
	return false
}

func replayOptionsForSession(opts capture.OfflineReplayOptions, s *sniffEventSession) capture.OfflineReplayOptions {
	before := opts.BeforePass
	opts.BeforePass = func(pass uint64) error {
		if before != nil {
			if err := before(pass); err != nil {
				return err
			}
		}
		if pass == 1 || s == nil {
			return nil
		}
		if err := s.analysis.Reset(); err != nil {
			return fmt.Errorf("reset replay analysis: %w", err)
		}
		if s.radius != nil {
			s.radius.Close()
			observer, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "local"})
			if err != nil {
				return fmt.Errorf("reset RADIUS observations: %w", err)
			}
			s.radius = observer
		}
		return nil
	}
	return opts
}

func waitReplayStartup(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
