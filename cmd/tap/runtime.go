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

// tapRuntimeAdapter binds flag-derived setup hooks to the single shared
// protocol definition. It is topology wiring, not another protocol spec.
type tapRuntimeAdapter struct {
	protocol        protocolcatalog.Spec
	ConfigureGPU    func(GPUConfig) GPUConfig
	ConfigureSource func(*source.LocalSource)
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
func newTapRuntime(config processor.Config, effectiveBPF string, adapter tapRuntimeAdapter) (*tapRuntime, error) {
	p, err := processor.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create processor: %w", err)
	}

	exclusionFilter := buildOwnTrafficExclusionFilter(config.ListenAddr, config.UpstreamAddr)
	effectiveBPF = combineFiltersWithExclusion(effectiveBPF, exclusionFilter)
	if exclusionFilter != "" {
		logger.Info("Own-traffic BPF exclusion applied", "exclusion", exclusionFilter, "effective_filter", effectiveBPF)
	}

	sourceConfig := tapSourceConfig(config, effectiveBPF, adapter.protocol)
	localSource := source.NewLocalSource(sourceConfig)
	localTarget := filtering.NewLocalTarget(filtering.LocalTargetConfig{BaseBPF: effectiveBPF})
	localTarget.SetBPFUpdater(localSource)

	gpuConfig := GetGPUConfig()
	if adapter.ConfigureGPU != nil {
		gpuConfig = adapter.ConfigureGPU(gpuConfig)
	}
	appFilter, err := createApplicationFilter(gpuConfig)
	if err != nil {
		return nil, err
	}
	localSource.SetApplicationFilter(appFilter)
	localTarget.SetApplicationFilter(appFilter)
	if adapter.ConfigureSource != nil {
		adapter.ConfigureSource(localSource)
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
	return source.LocalSourceConfig{
		Interfaces:   cmdutil.GetStringSliceConfig("tap.interfaces", interfaces),
		BPFFilter:    effectiveBPF,
		BatchSize:    cmdutil.GetIntConfig("tap.batch_size", batchSize),
		BatchTimeout: time.Duration(cmdutil.GetIntConfig("tap.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BufferSize:   cmdutil.GetIntConfig("tap.buffer_size", bufferSize),
		BatchBuffer:  1000,
		ProcessorID:  config.ProcessorID,
		ProtocolMode: protocol.Name,
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
