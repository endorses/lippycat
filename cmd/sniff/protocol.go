//go:build cli || all

package sniff

import (
	"context"
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/spf13/cobra"
)

// sniffRuntimeHooks binds flag-derived operations to a catalog protocol. It is
// topology wiring, not a second protocol specification.
type sniffRuntimeHooks struct {
	BuildBPF    func(baseFilter string) (string, error)
	StartLive   func(interfaces, filter string)
	StartFiles  func(files []string, filter string)
	StartReplay func(context.Context, []string, string, capture.OfflineReplayOptions) error
}

func (s sniffRuntimeHooks) validate(protocol protocolcatalog.Spec) error {
	if protocol.Name == "" || protocol.Analyzer == "" {
		return fmt.Errorf("protocol name is required")
	}
	if s.BuildBPF == nil {
		return fmt.Errorf("%s protocol BPF builder is required", protocol.Name)
	}
	if s.StartLive == nil {
		return fmt.Errorf("%s protocol live ingress is required", protocol.Name)
	}
	if s.StartFiles == nil && s.StartReplay == nil {
		return fmt.Errorf("%s protocol file ingress is required", protocol.Name)
	}
	return nil
}

func runProtocol(cmd *cobra.Command, args []string, protocol protocolcatalog.Spec, hooks sniffRuntimeHooks) error {
	if err := hooks.validate(protocol); err != nil {
		return err
	}
	if err := validateReplayOptions(cmd, args); err != nil {
		return err
	}
	effectiveFilter, err := hooks.BuildBPF(filter)
	if err != nil {
		return fmt.Errorf("%s protocol filter: %w", protocol.Name, err)
	}
	files := collectReadFiles(readFile, args)
	var runErr error
	analysisErr := withEventAnalysisMode(files, structuredLogAnalysisProfile(protocol.Name, effectiveFilter), effectiveFilter, false, func(session *sniffEventSession) {
		if protocol.Analyzer == protocolcatalog.AnalyzerTLS && session != nil {
			var previousClientHellos, previousECHOffers uint64
			restore := tls.SetObservationCountsProvider(func() (uint64, uint64) {
				session.analysis.EOF()
				stats := session.analysis.Stats()
				clientHellos := stats.TLSClientHelloCount - previousClientHellos
				echOffers := stats.TLSECHOfferedCount - previousECHOffers
				previousClientHellos, previousECHOffers = stats.TLSClientHelloCount, stats.TLSECHOfferedCount
				return clientHellos, echOffers
			})
			defer restore()
		}
		if len(files) == 0 {
			hooks.StartLive(interfaces, effectiveFilter)
			return
		}
		ctx, stop := offlineReplayContext(cmd)
		defer stop()
		opts := replayOptionsForSession(sniffReplayOptions(), session)
		if hooks.StartReplay == nil {
			if opts.Count != 1 || opts.Delay != 0 {
				runErr = fmt.Errorf("%s protocol replay ingress is required for loop options", protocol.Name)
				return
			}
			hooks.StartFiles(files, effectiveFilter)
			return
		}
		runErr = hooks.StartReplay(ctx, files, effectiveFilter, opts)
		if ctx.Err() != nil && onlyReplayCancellation(runErr) {
			runErr = nil
		}
	})
	return errors.Join(analysisErr, runErr)
}
