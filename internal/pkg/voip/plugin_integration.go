package voip

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip/plugins"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

// PluginPacketProcessor integrates the plugin system with packet processing
type PluginPacketProcessor struct {
	registry *plugins.PluginRegistry
	enabled  atomic.Bool
	stats    PluginProcessorStats
}

// PluginProcessorStats tracks plugin processor statistics
type PluginProcessorStats struct {
	PacketsProcessed atomic.Int64
	PluginHits       atomic.Int64
	PluginMisses     atomic.Int64
	ProcessingTime   atomic.Int64
	ErrorCount       atomic.Int64
}

// NewPluginPacketProcessor creates a new plugin packet processor
func NewPluginPacketProcessor() *PluginPacketProcessor {
	return &PluginPacketProcessor{
		registry: plugins.GetGlobalRegistry(),
	}
}

// Enable enables plugin packet processing
func (p *PluginPacketProcessor) Enable() {
	p.enabled.Store(true)
	logger.Info("Plugin packet processing enabled")
}

// Disable disables plugin packet processing
func (p *PluginPacketProcessor) Disable() {
	p.enabled.Store(false)
	logger.Info("Plugin packet processing disabled")
}

// IsEnabled returns whether plugin processing is enabled
func (p *PluginPacketProcessor) IsEnabled() bool {
	return p.enabled.Load()
}

// ProcessPacket processes a packet through the plugin system
func (p *PluginPacketProcessor) ProcessPacket(ctx context.Context, packet gopacket.Packet) ([]*plugins.ProcessResult, error) {
	if !p.enabled.Load() || !p.registry.IsEnabled() {
		return nil, nil
	}

	start := time.Now()
	defer func() {
		processingTime := time.Since(start)
		p.stats.PacketsProcessed.Add(1)
		p.stats.ProcessingTime.Add(processingTime.Nanoseconds())
	}()

	// Process packet through plugin registry
	results, err := p.registry.ProcessPacket(ctx, packet)
	if err != nil {
		p.stats.ErrorCount.Add(1)
		logger.Error("Plugin packet processing error", "error", err)
		return nil, err
	}

	if len(results) > 0 {
		p.stats.PluginHits.Add(1)

		// Process results and integrate with existing call tracking
		for _, result := range results {
			if err := p.integrateResult(result, packet); err != nil {
				logger.Error("Failed to integrate plugin result",
					"call_id", result.CallID,
					"protocol", result.Protocol,
					"error", err)
			}
		}
	} else {
		p.stats.PluginMisses.Add(1)
	}

	return results, nil
}

// integrateResult integrates plugin results with existing VoIP processing
func (p *PluginPacketProcessor) integrateResult(result *plugins.ProcessResult, packet gopacket.Packet) error {
	// Skip integration if no call ID
	if result.CallID == "" {
		return nil
	}

	// Get or create call using existing call tracker
	// Use Ethernet as default link type since packet doesn't have LinkType method
	linkType := layers.LinkTypeEthernet

	var call *CallInfo
	if IsLockFreeModeEnabled() {
		call = GetOrCreateCallLockFree(result.CallID, linkType)
	} else {
		call = GetOrCreateCall(result.CallID, linkType)
	}

	if call == nil {
		return nil
	}

	// Update call state based on plugin action
	switch result.Action {
	case "call_start":
		if IsLockFreeModeEnabled() {
			GetHybridTracker().SetCallState(result.CallID, "ACTIVE")
		} else {
			call.SetCallInfoState("ACTIVE")
		}
	case "call_end":
		if IsLockFreeModeEnabled() {
			GetHybridTracker().SetCallState(result.CallID, "TERMINATED")
		} else {
			call.SetCallInfoState("TERMINATED")
		}
	case "call_cancel":
		if IsLockFreeModeEnabled() {
			GetHybridTracker().SetCallState(result.CallID, "CANCELLED")
		} else {
			call.SetCallInfoState("CANCELLED")
		}
	}

	// Add port mappings for RTP streams
	if result.Protocol == "rtp" || result.Protocol == "sip" {
		if srcPort, ok := result.Metadata["src_port"].(string); ok {
			if IsLockFreeModeEnabled() {
				AddPortMappingLockFree(srcPort, result.CallID)
			} else {
				// Use traditional method
				tracker := getTracker()
				tracker.mu.Lock()
				tracker.portToCallID[srcPort] = result.CallID
				tracker.mu.Unlock()
			}
		}

		if dstPort, ok := result.Metadata["dst_port"].(string); ok {
			if IsLockFreeModeEnabled() {
				AddPortMappingLockFree(dstPort, result.CallID)
			} else {
				// Use traditional method
				tracker := getTracker()
				tracker.mu.Lock()
				tracker.portToCallID[dstPort] = result.CallID
				tracker.mu.Unlock()
			}
		}
	}

	// Write packet to appropriate files if writeVoip is enabled
	if viper.GetBool("writeVoip") && call != nil {
		switch result.Protocol {
		case "sip":
			if call.SIPWriter != nil {
				if err := call.SIPWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					logger.Error("Failed to write SIP packet", "error", err)
				}
			}
		case "rtp":
			if call.RTPWriter != nil {
				if err := call.RTPWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					logger.Error("Failed to write RTP packet", "error", err)
				}
			}
		}
	}

	return nil
}

// GetStats returns processor statistics
func (p *PluginPacketProcessor) GetStats() PluginProcessorStats {
	return PluginProcessorStats{
		PacketsProcessed: atomic.Int64{},
		PluginHits:       atomic.Int64{},
		PluginMisses:     atomic.Int64{},
		ProcessingTime:   atomic.Int64{},
		ErrorCount:       atomic.Int64{},
	}
}

// GetRegistry returns the plugin registry
func (p *PluginPacketProcessor) GetRegistry() *plugins.PluginRegistry {
	return p.registry
}

// Global plugin processor instance
var (
	globalPluginProcessor *PluginPacketProcessor
	pluginProcessorOnce   sync.Once
)

// GetGlobalPluginProcessor returns the global plugin processor
func GetGlobalPluginProcessor() *PluginPacketProcessor {
	pluginProcessorOnce.Do(func() {
		globalPluginProcessor = NewPluginPacketProcessor()
	})
	return globalPluginProcessor
}

// InitializePluginProcessing initializes plugin-based packet processing
func InitializePluginProcessing() error {
	logger.Info("Initializing plugin-based packet processing")

	// Initialize the plugin system
	if err := plugins.InitializePluginSystem(); err != nil {
		return err
	}

	// Enable the processor
	processor := GetGlobalPluginProcessor()
	processor.Enable()

	logger.Info("Plugin-based packet processing initialized")
	return nil
}

// ShutdownPluginProcessing gracefully shuts down plugin processing
func ShutdownPluginProcessing(ctx context.Context) error {
	logger.Info("Shutting down plugin-based packet processing")

	processor := GetGlobalPluginProcessor()
	processor.Disable()

	// Shutdown the plugin system
	if err := plugins.ShutdownPluginSystem(ctx); err != nil {
		return err
	}

	logger.Info("Plugin-based packet processing shutdown complete")
	return nil
}

// EnablePluginProcessingForConfig enables plugin processing based on configuration
func EnablePluginProcessingForConfig() {
	if viper.GetBool("plugins.enabled") {
		if err := InitializePluginProcessing(); err != nil {
			logger.Error("Failed to initialize plugin processing", "error", err)
		} else {
			logger.Info("Plugin processing enabled via configuration")
		}
	} else {
		logger.Debug("Plugin processing disabled via configuration")
	}
}

// ProcessPacketWithPlugins processes a packet through both traditional and plugin systems
func ProcessPacketWithPlugins(ctx context.Context, packet gopacket.Packet) error {
	// Process through plugin system if enabled
	processor := GetGlobalPluginProcessor()
	if processor.IsEnabled() {
		if _, err := processor.ProcessPacket(ctx, packet); err != nil {
			logger.Error("Plugin processing error", "error", err)
			// Continue with traditional processing on plugin error
		}
	}

	// Traditional processing can still run in parallel
	// This allows for gradual migration to plugin-based processing
	return nil
}

// GetPluginProcessingStats returns comprehensive plugin processing statistics
func GetPluginProcessingStats() map[string]interface{} {
	processor := GetGlobalPluginProcessor()
	registry := processor.GetRegistry()
	loader := plugins.GetGlobalPluginLoader()

	stats := map[string]interface{}{
		"processor": map[string]interface{}{
			"enabled":           processor.IsEnabled(),
			"packets_processed": processor.stats.PacketsProcessed.Load(),
			"plugin_hits":       processor.stats.PluginHits.Load(),
			"plugin_misses":     processor.stats.PluginMisses.Load(),
			"processing_time":   processor.stats.ProcessingTime.Load(),
			"error_count":       processor.stats.ErrorCount.Load(),
		},
		"registry": registry.GetStats(),
		"loader":   loader.GetPluginStats(),
		"plugins":  registry.ListPlugins(),
	}

	return stats
}
