package plugins

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// PluginRegistry manages all loaded plugins
type PluginRegistry struct {
	plugins        map[string]ProtocolHandler
	pluginConfigs  map[string]PluginConfig
	pluginInfos    map[string]PluginInfo
	protocolMap    map[string][]string // protocol -> plugin names
	eventHandlers  []EventHandler
	mu             sync.RWMutex
	enabled        atomic.Bool
	stats          RegistryStats
}

// RegistryStats contains statistics about the plugin registry
type RegistryStats struct {
	TotalPlugins     atomic.Int64
	ActivePlugins    atomic.Int64
	PacketsProcessed atomic.Int64
	ProcessingTime   atomic.Int64 // nanoseconds
	ErrorCount       atomic.Int64
	LastError        atomic.Value  // string
	LastErrorTime    atomic.Int64  // unix timestamp
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins:       make(map[string]ProtocolHandler),
		pluginConfigs: make(map[string]PluginConfig),
		pluginInfos:   make(map[string]PluginInfo),
		protocolMap:   make(map[string][]string),
		eventHandlers: make([]EventHandler, 0),
	}
}

// Enable enables the plugin system
func (r *PluginRegistry) Enable() {
	r.enabled.Store(true)
	logger.Info("Plugin registry enabled")
}

// Disable disables the plugin system
func (r *PluginRegistry) Disable() {
	r.enabled.Store(false)
	logger.Info("Plugin registry disabled")
}

// IsEnabled returns whether the plugin system is enabled
func (r *PluginRegistry) IsEnabled() bool {
	return r.enabled.Load()
}

// RegisterPlugin registers a new plugin
func (r *PluginRegistry) RegisterPlugin(name string, plugin ProtocolHandler, config PluginConfig) error {
	if !r.IsEnabled() {
		return fmt.Errorf("plugin registry is disabled")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if plugin already exists
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	// Initialize the plugin
	configMap := make(map[string]interface{})
	if config.Settings != nil {
		configMap = config.Settings
	}

	if err := plugin.Initialize(configMap); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
	}

	// Register the plugin
	r.plugins[name] = plugin
	r.pluginConfigs[name] = config

	// Create plugin info
	info := PluginInfo{
		Name:        plugin.Name(),
		Version:     plugin.Version(),
		Description: fmt.Sprintf("Protocol handler for %v", plugin.SupportedProtocols()),
		Protocols:   plugin.SupportedProtocols(),
		Config:      config,
		LoadTime:    time.Now(),
	}
	r.pluginInfos[name] = info

	// Update protocol mapping
	for _, protocol := range plugin.SupportedProtocols() {
		if r.protocolMap[protocol] == nil {
			r.protocolMap[protocol] = make([]string, 0)
		}
		r.protocolMap[protocol] = append(r.protocolMap[protocol], name)

		// Sort by priority (higher priority first)
		sort.Slice(r.protocolMap[protocol], func(i, j int) bool {
			pi := r.pluginConfigs[r.protocolMap[protocol][i]].Priority
			pj := r.pluginConfigs[r.protocolMap[protocol][j]].Priority
			return pi > pj
		})
	}

	r.stats.TotalPlugins.Add(1)
	if config.Enabled {
		r.stats.ActivePlugins.Add(1)
	}

	// Emit event
	r.emitEvent(PluginEvent{
		Type:       EventPluginLoaded,
		PluginName: name,
		Timestamp:  time.Now(),
		Data:       info,
	})

	logger.Info("Plugin registered successfully",
		"name", name,
		"version", plugin.Version(),
		"protocols", plugin.SupportedProtocols())

	return nil
}

// UnregisterPlugin removes a plugin from the registry
func (r *PluginRegistry) UnregisterPlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	plugin, exists := r.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	// Shutdown the plugin
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := plugin.Shutdown(ctx); err != nil {
		logger.Error("Error shutting down plugin", "name", name, "error", err)
	}

	// Remove from protocol mapping
	for _, protocol := range plugin.SupportedProtocols() {
		if plugins, ok := r.protocolMap[protocol]; ok {
			// Remove plugin from slice
			for i, pluginName := range plugins {
				if pluginName == name {
					r.protocolMap[protocol] = append(plugins[:i], plugins[i+1:]...)
					break
				}
			}
			// Clean up empty slices
			if len(r.protocolMap[protocol]) == 0 {
				delete(r.protocolMap, protocol)
			}
		}
	}

	// Remove from registry
	delete(r.plugins, name)
	config := r.pluginConfigs[name]
	delete(r.pluginConfigs, name)
	delete(r.pluginInfos, name)

	r.stats.TotalPlugins.Add(-1)
	if config.Enabled {
		r.stats.ActivePlugins.Add(-1)
	}

	// Emit event
	r.emitEvent(PluginEvent{
		Type:       EventPluginUnloaded,
		PluginName: name,
		Timestamp:  time.Now(),
	})

	logger.Info("Plugin unregistered successfully", "name", name)
	return nil
}

// ProcessPacket processes a packet through all relevant plugins
func (r *PluginRegistry) ProcessPacket(ctx context.Context, packet gopacket.Packet) ([]*ProcessResult, error) {
	if !r.IsEnabled() {
		return nil, nil
	}

	start := time.Now()
	defer func() {
		processingTime := time.Since(start)
		r.stats.PacketsProcessed.Add(1)
		r.stats.ProcessingTime.Add(processingTime.Nanoseconds())
	}()

	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []*ProcessResult
	var firstError error

	// Try to detect protocols and run appropriate plugins
	detectedProtocols := r.detectProtocols(packet)

	for _, protocol := range detectedProtocols {
		pluginNames, exists := r.protocolMap[protocol]
		if !exists {
			continue
		}

		for _, pluginName := range pluginNames {
			config := r.pluginConfigs[pluginName]
			if !config.Enabled {
				continue
			}

			plugin := r.plugins[pluginName]

			// Create timeout context for plugin
			pluginCtx := ctx
			if config.Timeout > 0 {
				var cancel context.CancelFunc
				pluginCtx, cancel = context.WithTimeout(ctx, config.Timeout)
				defer cancel()
			}

			// Process packet with plugin
			result, err := plugin.ProcessPacket(pluginCtx, packet)
			if err != nil {
				r.handlePluginError(pluginName, "ProcessPacket", err)
				if firstError == nil {
					firstError = err
				}
				continue
			}

			if result != nil {
				results = append(results, result)

				// Check if we should continue processing
				if !result.ShouldContinue {
					break
				}
			}
		}
	}

	return results, firstError
}

// detectProtocols attempts to detect protocols in the packet
func (r *PluginRegistry) detectProtocols(packet gopacket.Packet) []string {
	var protocols []string

	// Check common VoIP protocols
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		if len(payload) > 0 {
			// Simple heuristics for protocol detection
			maxLen := len(payload)
			if maxLen > 100 {
				maxLen = 100
			}
			payloadStr := string(payload[:maxLen])

			if contains(payloadStr, "SIP/2.0") || contains(payloadStr, "INVITE") || contains(payloadStr, "REGISTER") {
				protocols = append(protocols, "sip")
			}

			if contains(payloadStr, "RTCP") || len(payload) >= 12 && payload[0] >= 128 && payload[0] <= 191 {
				protocols = append(protocols, "rtp")
			}

			if contains(payloadStr, "H.323") || contains(payloadStr, "Q.931") {
				protocols = append(protocols, "h323")
			}
		}
	}

	// If no specific protocol detected, use generic
	if len(protocols) == 0 {
		protocols = append(protocols, "generic")
	}

	return protocols
}

// GetPlugin returns a plugin by name
func (r *PluginRegistry) GetPlugin(name string) (ProtocolHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, exists := r.plugins[name]
	return plugin, exists
}

// ListPlugins returns all registered plugins
func (r *PluginRegistry) ListPlugins() map[string]PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]PluginInfo)
	for name, info := range r.pluginInfos {
		result[name] = info
	}
	return result
}

// GetPluginsByProtocol returns plugins that handle a specific protocol
func (r *PluginRegistry) GetPluginsByProtocol(protocol string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if plugins, exists := r.protocolMap[protocol]; exists {
		result := make([]string, len(plugins))
		copy(result, plugins)
		return result
	}
	return nil
}

// EnablePlugin enables a specific plugin
func (r *PluginRegistry) EnablePlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	config, exists := r.pluginConfigs[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	if !config.Enabled {
		config.Enabled = true
		r.pluginConfigs[name] = config
		r.stats.ActivePlugins.Add(1)
		logger.Info("Plugin enabled", "name", name)
	}

	return nil
}

// DisablePlugin disables a specific plugin
func (r *PluginRegistry) DisablePlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	config, exists := r.pluginConfigs[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	if config.Enabled {
		config.Enabled = false
		r.pluginConfigs[name] = config
		r.stats.ActivePlugins.Add(-1)
		logger.Info("Plugin disabled", "name", name)
	}

	return nil
}

// AddEventHandler adds an event handler
func (r *PluginRegistry) AddEventHandler(handler EventHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventHandlers = append(r.eventHandlers, handler)
}

// GetStats returns current registry statistics
func (r *PluginRegistry) GetStats() RegistryStats {
	return r.stats
}

// HealthCheck returns the health status of all plugins
func (r *PluginRegistry) HealthCheck() map[string]HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]HealthStatus)
	for name, plugin := range r.plugins {
		if r.pluginConfigs[name].Enabled {
			result[name] = plugin.HealthCheck()
		}
	}
	return result
}

// Shutdown gracefully shuts down all plugins
func (r *PluginRegistry) Shutdown(ctx context.Context) error {
	logger.Info("Shutting down plugin registry")

	r.mu.Lock()
	defer r.mu.Unlock()

	var errors []error
	for name, plugin := range r.plugins {
		if err := plugin.Shutdown(ctx); err != nil {
			errors = append(errors, fmt.Errorf("plugin %s: %w", name, err))
		}
	}

	// Clear all plugins
	r.plugins = make(map[string]ProtocolHandler)
	r.pluginConfigs = make(map[string]PluginConfig)
	r.pluginInfos = make(map[string]PluginInfo)
	r.protocolMap = make(map[string][]string)

	r.stats.TotalPlugins.Store(0)
	r.stats.ActivePlugins.Store(0)

	logger.Info("Plugin registry shutdown complete")

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}
	return nil
}

// Helper functions

func (r *PluginRegistry) handlePluginError(pluginName, operation string, err error) {
	r.stats.ErrorCount.Add(1)
	r.stats.LastError.Store(err.Error())
	r.stats.LastErrorTime.Store(time.Now().Unix())

	pluginErr := &PluginError{
		PluginName: pluginName,
		Operation:  operation,
		Err:        err,
		Timestamp:  time.Now(),
	}

	r.emitEvent(PluginEvent{
		Type:       EventPluginError,
		PluginName: pluginName,
		Timestamp:  time.Now(),
		Data:       pluginErr,
	})

	logger.Error("Plugin error", "plugin", pluginName, "operation", operation, "error", err)
}

func (r *PluginRegistry) emitEvent(event PluginEvent) {
	for _, handler := range r.eventHandlers {
		go func(h EventHandler) {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Event handler panic", "event", event.Type, "error", r)
				}
			}()
			h(event)
		}(handler)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

// Global plugin registry instance
var (
	globalPluginRegistry *PluginRegistry
	pluginRegistryOnce   sync.Once
)

// GetGlobalRegistry returns the global plugin registry
func GetGlobalRegistry() *PluginRegistry {
	pluginRegistryOnce.Do(func() {
		globalPluginRegistry = NewPluginRegistry()
	})
	return globalPluginRegistry
}