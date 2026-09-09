//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/pkg/signals"
)

// tapRuntimeHooks binds flag-derived setup hooks to a catalog protocol. It is
// topology wiring, not a second protocol specification.
type tapRuntimeHooks struct {
	ConfigureGPU          func(GPUConfig) GPUConfig
	ConfigureSource       func(*source.LocalSource)
	ConfigureSourceConfig func(*source.LocalSourceConfig)
}

type tapRuntime struct {
	processor    *processor.Processor
	localSource  *source.LocalSource
	appFilter    *hunter.ApplicationFilter
	sourceConfig source.LocalSourceConfig
	mode         string
	startHook    func(context.Context)
}

// newTapRuntime constructs the shared processor/source/filter graph used by tap
// protocol commands.
func newTapRuntime(config processor.Config, effectiveBPF string, protocol protocolcatalog.Spec, hooks tapRuntimeHooks) (*tapRuntime, error) {
	if protocol.Name == "" || protocol.Analyzer == "" {
		return nil, fmt.Errorf("protocol catalog specification is incomplete")
	}
	if err := applyRADIUSLIConfig(nil, &config); err != nil {
		return nil, err
	}
	sourceConfig := tapSourceConfig(config, effectiveBPF, protocol)
	if hooks.ConfigureSourceConfig != nil {
		hooks.ConfigureSourceConfig(&sourceConfig)
	}
	if protocol.Name == "radius" && config.LIEnabled {
		scope := config.LIRADIUSScope
		captureTimeout := sourceConfig.RADIUSCorrelation.Lifetime
		if captureTimeout == 0 {
			captureTimeout = 30 * time.Second
		}
		if config.LIRADIUSCorrelationLifetime != captureTimeout {
			return nil, fmt.Errorf("RADIUS capture and LI transaction timeouts must agree")
		}
		if scope.OperatorScope == "" || scope.ProfileRevision == "" {
			return nil, fmt.Errorf("tap radius LI requires explicit LI operator scope and profile revision")
		}
		if scope.OperatorScope != sourceConfig.RADIUSScope.OperatorScope || scope.ProfileRevision != sourceConfig.RADIUSScope.ProfileRevision {
			return nil, fmt.Errorf("RADIUS capture and LI operator scope/profile revision must agree")
		}
		if scope.OriginNodeID != "" && scope.OriginNodeID != config.ProcessorID+"-local" {
			return nil, fmt.Errorf("RADIUS LI origin node must match tap source ID (processor ID plus -local)")
		}
		if scope.SourceID != "" {
			found := false
			for _, name := range sourceConfig.Interfaces {
				if name == scope.SourceID {
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("RADIUS LI source must name a configured tap interface")
			}
		}
		if config.LIRADIUSCorrelationStateFile == "" && config.LIStateFile == "" {
			return nil, fmt.Errorf("RADIUS X2 requires a durable correlation state file or LI state file")
		}
	}
	p, err := processor.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create processor: %w", err)
	}

	exclusionFilter := buildOwnTrafficExclusionFilter(config.ListenAddr, config.UpstreamAddr)
	effectiveBPF = combineFiltersWithExclusion(effectiveBPF, exclusionFilter)
	if exclusionFilter != "" {
		logger.Info("Own-traffic BPF exclusion applied", "exclusion", exclusionFilter, "effective_filter", effectiveBPF)
	}

	sourceConfig.BPFFilter = effectiveBPF
	localSource := source.NewLocalSource(sourceConfig)
	localTarget := filtering.NewLocalTarget(filtering.LocalTargetConfig{BaseBPF: effectiveBPF})
	localTarget.SetBPFUpdater(localSource)

	gpuConfig := GetGPUConfig()
	if hooks.ConfigureGPU != nil {
		gpuConfig = hooks.ConfigureGPU(gpuConfig)
	}
	appFilter, err := createApplicationFilter(gpuConfig)
	if err != nil {
		return nil, err
	}
	localSource.SetApplicationFilter(appFilter)
	localTarget.SetApplicationFilter(appFilter)
	if hooks.ConfigureSource != nil {
		hooks.ConfigureSource(localSource)
	}

	p.SetPacketSource(localSource)
	p.SetFilterTarget(localTarget)
	mode := "standalone"
	if config.UpstreamAddr != "" {
		mode = "hierarchical"
	}
	return &tapRuntime{
		processor:    p,
		localSource:  localSource,
		appFilter:    appFilter,
		sourceConfig: sourceConfig,
		mode:         mode,
	}, nil
}

func tapSourceConfig(config processor.Config, effectiveBPF string, protocol protocolcatalog.Spec) source.LocalSourceConfig {
	includeHTTPHeaders := config.LogConfig != nil && config.LogConfig.IncludeHTTPHeaders
	return source.LocalSourceConfig{
		Interfaces:         cmdutil.GetStringSliceConfig("tap.interfaces", interfaces),
		BPFFilter:          effectiveBPF,
		BatchSize:          cmdutil.GetIntConfig("tap.batch_size", batchSize),
		BatchTimeout:       time.Duration(cmdutil.GetIntConfig("tap.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BufferSize:         cmdutil.GetIntConfig("tap.buffer_size", bufferSize),
		BatchBuffer:        1000,
		ProcessorID:        config.ProcessorID,
		ProtocolMode:       string(protocol.Analyzer),
		IncludeHTTPHeaders: includeHTTPHeaders,
	}
}

func (r *tapRuntime) run(nodeName string, config processor.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup := signals.SetupHandler(ctx, cancel)
	defer cleanup()

	errChan := make(chan error, constants.ErrorChannelBuffer)
	go func() {
		if err := r.processor.Start(ctx); err != nil {
			errChan <- err
		}
	}()
	if r.startHook != nil {
		r.startHook(ctx)
	}
	logger.Info(nodeName+" started successfully", "listen", config.ListenAddr, "mode", r.mode)

	select {
	case <-ctx.Done():
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error(nodeName+" failed", "error", err)
		return err
	}
	logger.Info(nodeName + " stopped")
	return nil
}
