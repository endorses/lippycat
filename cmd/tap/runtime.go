//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"strings"
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
	"github.com/spf13/viper"
)

// tapRuntimeHooks binds flag-derived setup hooks to a catalog protocol. It is
// topology wiring, not a second protocol specification.
type tapRuntimeHooks struct {
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
func newTapRuntime(config processor.Config, effectiveBPF string, protocol protocolcatalog.Spec, hooks tapRuntimeHooks) (*tapRuntime, error) {
	if protocol.Name == "" || protocol.Analyzer == "" {
		return nil, fmt.Errorf("protocol catalog specification is incomplete")
	}
	if err := applyTapEventTransportConfig(&config); err != nil {
		return nil, err
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

	sourceConfig := tapSourceConfig(config, effectiveBPF, protocol)
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

func applyTapEventTransportConfig(config *processor.Config) error {
	config.UpstreamForwardMode = strings.ToLower(cmdutil.GetStringConfig("tap.forward_mode", forwardMode))
	config.UpstreamEventFallbackToPackets = cmdutil.GetBoolConfig("tap.events.fallback_to_packets", eventFallbackToPackets)
	config.UpstreamEventDeliveryProfile = normalizeEventProfile(cmdutil.GetStringConfig("tap.events.delivery_profile", eventDeliveryProfile))
	config.UpstreamEventSpoolDirectory = cmdutil.GetStringConfig("tap.events.spool.dir", eventSpoolDir)
	config.UpstreamEventSpoolMaxBytes = viper.GetUint64("tap.events.spool.max_bytes")
	config.UpstreamEventSpoolMaxAge = viper.GetDuration("tap.events.spool.max_age")
	config.UpstreamEventSpoolExhaustionPolicy = strings.ToLower(cmdutil.GetStringConfig("tap.events.spool.exhaustion_policy", eventSpoolExhaustionPolicy))
	config.EventIngressProfile = normalizeEventProfile(cmdutil.GetStringConfig("tap.events.ingress.profile", eventIngressProfile))
	config.EventIngressWALDirectory = cmdutil.GetStringConfig("tap.events.ingress.wal_dir", eventIngressWALDir)
	config.EventIngressWALMaxBytes = viper.GetInt64("tap.events.ingress.wal_max_bytes")
	config.EventIngressMaxBatchBytes = cmdutil.GetIntConfig("tap.events.ingress.max_batch_bytes", eventIngressMaxBatchBytes)

	if config.UpstreamForwardMode != "packets" && config.UpstreamForwardMode != "events" {
		return fmt.Errorf("invalid forward mode %q: must be packets or events", config.UpstreamForwardMode)
	}
	if config.UpstreamEventDeliveryProfile != "reliable" && config.UpstreamEventDeliveryProfile != "memory_only" {
		return fmt.Errorf("invalid event delivery profile %q: must be reliable or memory-only", config.UpstreamEventDeliveryProfile)
	}
	if config.UpstreamEventFallbackToPackets && config.UpstreamForwardMode != "events" {
		return fmt.Errorf("event fallback to packets is only valid with --forward-mode=events")
	}
	if config.UpstreamEventSpoolExhaustionPolicy != "drop_oldest" && config.UpstreamEventSpoolExhaustionPolicy != "drop_new" {
		return fmt.Errorf("invalid event spool exhaustion policy %q: must be drop_oldest or drop_new", config.UpstreamEventSpoolExhaustionPolicy)
	}
	if config.UpstreamForwardMode == "events" && config.UpstreamEventDeliveryProfile == "reliable" && config.UpstreamEventSpoolDirectory == "" {
		return fmt.Errorf("reliable upstream event delivery requires a non-empty event spool directory")
	}
	if config.EventIngressProfile != "reliable" && config.EventIngressProfile != "memory_only" {
		return fmt.Errorf("invalid event ingress profile %q: must be reliable or memory-only", config.EventIngressProfile)
	}
	if config.EventIngressProfile == "reliable" && config.EventIngressWALDirectory == "" {
		return fmt.Errorf("reliable event ingress requires --event-ingress-wal-dir")
	}
	if config.EventIngressWALMaxBytes < 0 || config.EventIngressMaxBatchBytes <= 0 {
		return fmt.Errorf("event ingress limits must be non-negative and max batch bytes must be positive")
	}
	return nil
}

func normalizeEventProfile(profile string) string {
	return strings.ReplaceAll(strings.ToLower(profile), "-", "_")
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
