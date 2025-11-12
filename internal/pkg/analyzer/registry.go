package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// Registry manages all registered protocol analyzers.
//
// The registry uses compile-time registration where protocol analyzers register
// themselves via init() functions. This approach provides:
//   - Cross-platform compatibility (no dynamic .so loading)
//   - Type safety (compile-time checking)
//   - High performance (no dynamic loading overhead)
//   - Simple maintenance (standard Go interfaces)
//
// Thread-safe for concurrent registration and packet processing.
type Registry struct {
	protocols   map[string]Protocol // name -> protocol analyzer
	configs     map[string]Config   // name -> configuration
	infos       map[string]Info     // name -> metadata
	protocolMap map[string][]string // protocol -> analyzer names
	mu          sync.RWMutex        // protects all maps
	enabled     atomic.Bool         // global enable/disable
	stats       Stats               // registry statistics
}

// Stats contains statistics about the protocol registry
type Stats struct {
	TotalProtocols   atomic.Int64
	ActiveProtocols  atomic.Int64
	PacketsProcessed atomic.Int64
	ProcessingTime   atomic.Int64 // nanoseconds
	ErrorCount       atomic.Int64
	LastError        atomic.Value // string
	LastErrorTime    atomic.Int64 // unix timestamp
}

// newRegistry creates a new protocol registry.
// Use GetRegistry() to access the singleton instance.
func newRegistry() *Registry {
	return &Registry{
		protocols:   make(map[string]Protocol),
		configs:     make(map[string]Config),
		infos:       make(map[string]Info),
		protocolMap: make(map[string][]string),
	}
}

// Enable enables the protocol analysis system
func (r *Registry) Enable() {
	r.enabled.Store(true)
	logger.Info("Protocol registry enabled")
}

// Disable disables the protocol analysis system
func (r *Registry) Disable() {
	r.enabled.Store(false)
	logger.Info("Protocol registry disabled")
}

// IsEnabled returns whether the protocol analysis system is enabled
func (r *Registry) IsEnabled() bool {
	return r.enabled.Load()
}

// Register registers a new protocol analyzer.
//
// Typically called from init() functions in protocol module files.
// Returns an error if the analyzer is already registered or initialization fails.
func (r *Registry) Register(name string, protocol Protocol, config Config) error {
	if !r.IsEnabled() {
		return fmt.Errorf("protocol registry is disabled")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if protocol already exists
	if _, exists := r.protocols[name]; exists {
		return fmt.Errorf("protocol %s already registered", name)
	}

	// Initialize the protocol
	configMap := make(map[string]interface{})
	if config.Settings != nil {
		configMap = config.Settings
	}

	if err := protocol.Initialize(configMap); err != nil {
		return fmt.Errorf("failed to initialize protocol %s: %w", name, err)
	}

	// Register the protocol
	r.protocols[name] = protocol
	r.configs[name] = config

	// Create protocol info
	info := Info{
		Name:        protocol.Name(),
		Version:     protocol.Version(),
		Description: fmt.Sprintf("Protocol analyzer for %v", protocol.SupportedProtocols()),
		Protocols:   protocol.SupportedProtocols(),
		Config:      config,
		LoadTime:    time.Now(),
	}
	r.infos[name] = info

	// Update protocol mapping
	for _, proto := range protocol.SupportedProtocols() {
		if r.protocolMap[proto] == nil {
			r.protocolMap[proto] = make([]string, 0)
		}
		r.protocolMap[proto] = append(r.protocolMap[proto], name)

		// Sort by priority (higher priority first)
		sort.Slice(r.protocolMap[proto], func(i, j int) bool {
			pi := r.configs[r.protocolMap[proto][i]].Priority
			pj := r.configs[r.protocolMap[proto][j]].Priority
			return pi > pj
		})
	}

	r.stats.TotalProtocols.Add(1)
	if config.Enabled {
		r.stats.ActiveProtocols.Add(1)
	}

	logger.Info("Protocol analyzer registered",
		"name", name,
		"version", protocol.Version(),
		"protocols", protocol.SupportedProtocols())

	return nil
}

// MustRegister registers a protocol analyzer and panics on error.
//
// Use this in init() functions for fail-fast behavior during startup.
func (r *Registry) MustRegister(name string, protocol Protocol, config Config) {
	if err := r.Register(name, protocol, config); err != nil {
		panic(fmt.Sprintf("failed to register protocol %s: %v", name, err))
	}
}

// Unregister removes a protocol analyzer from the registry
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	protocol, exists := r.protocols[name]
	if !exists {
		return fmt.Errorf("protocol %s not found", name)
	}

	// Shutdown the protocol
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := protocol.Shutdown(ctx); err != nil {
		logger.Error("Error shutting down protocol", "name", name, "error", err)
	}

	// Remove from protocol mapping
	for _, proto := range protocol.SupportedProtocols() {
		if protocols, ok := r.protocolMap[proto]; ok {
			// Remove protocol from slice
			for i, protocolName := range protocols {
				if protocolName == name {
					r.protocolMap[proto] = append(protocols[:i], protocols[i+1:]...)
					break
				}
			}
			// Clean up empty slices
			if len(r.protocolMap[proto]) == 0 {
				delete(r.protocolMap, proto)
			}
		}
	}

	// Remove from registry
	delete(r.protocols, name)
	config := r.configs[name]
	delete(r.configs, name)
	delete(r.infos, name)

	r.stats.TotalProtocols.Add(-1)
	if config.Enabled {
		r.stats.ActiveProtocols.Add(-1)
	}

	logger.Info("Protocol analyzer unregistered", "name", name)
	return nil
}

// ProcessPacket processes a packet through all relevant protocol analyzers
func (r *Registry) ProcessPacket(ctx context.Context, packet gopacket.Packet) ([]*Result, error) {
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

	var results []*Result
	var firstError error

	// Detect protocols and run appropriate analyzers
	detectedProtocols := r.detectProtocols(packet)

	for _, proto := range detectedProtocols {
		analyzerNames, exists := r.protocolMap[proto]
		if !exists {
			continue
		}

		for _, analyzerName := range analyzerNames {
			config := r.configs[analyzerName]
			if !config.Enabled {
				continue
			}

			analyzer := r.protocols[analyzerName]

			// Create timeout context for analyzer
			analyzerCtx := ctx
			if config.Timeout > 0 {
				var cancel context.CancelFunc
				analyzerCtx, cancel = context.WithTimeout(ctx, config.Timeout)
				defer cancel()
			}

			// Process packet with analyzer
			result, err := analyzer.ProcessPacket(analyzerCtx, packet)
			if err != nil {
				r.handleAnalyzerError(analyzerName, "ProcessPacket", err)
				if firstError == nil {
					firstError = err
				}
				continue
			}

			if result != nil {
				results = append(results, result)

				// Check if we should continue processing
				if !result.ShouldContinue {
					return results, firstError
				}
			}
		}
	}

	return results, firstError
}

// detectProtocols attempts to detect protocols in the packet using centralized detector
func (r *Registry) detectProtocols(packet gopacket.Packet) []string {
	var protocols []string

	// Use centralized detector without cache to avoid test cross-contamination
	detectionResult := detector.GetDefault().DetectWithoutCache(packet)
	if detectionResult != nil && detectionResult.Protocol != "unknown" {
		// Normalize protocol name to lowercase for analyzer mapping
		protocolName := strings.ToLower(detectionResult.Protocol)
		protocols = append(protocols, protocolName)
	}

	// If no specific protocol detected, use generic
	if len(protocols) == 0 {
		protocols = append(protocols, "generic")
	}

	return protocols
}

// Get returns a protocol analyzer by name
func (r *Registry) Get(name string) (Protocol, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	protocol, exists := r.protocols[name]
	return protocol, exists
}

// List returns all registered protocol analyzers
func (r *Registry) List() map[string]Info {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]Info)
	for name, info := range r.infos {
		result[name] = info
	}
	return result
}

// GetByProtocol returns analyzer names that handle a specific protocol
func (r *Registry) GetByProtocol(protocol string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if analyzers, exists := r.protocolMap[protocol]; exists {
		result := make([]string, len(analyzers))
		copy(result, analyzers)
		return result
	}
	return nil
}

// Enable enables a specific protocol analyzer
func (r *Registry) EnableProtocol(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	config, exists := r.configs[name]
	if !exists {
		return fmt.Errorf("protocol %s not found", name)
	}

	if !config.Enabled {
		config.Enabled = true
		r.configs[name] = config
		r.stats.ActiveProtocols.Add(1)
		logger.Info("Protocol analyzer enabled", "name", name)
	}

	return nil
}

// DisableProtocol disables a specific protocol analyzer
func (r *Registry) DisableProtocol(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	config, exists := r.configs[name]
	if !exists {
		return fmt.Errorf("protocol %s not found", name)
	}

	if config.Enabled {
		config.Enabled = false
		r.configs[name] = config
		r.stats.ActiveProtocols.Add(-1)
		logger.Info("Protocol analyzer disabled", "name", name)
	}

	return nil
}

// GetStats returns current registry statistics
func (r *Registry) GetStats() *Stats {
	return &r.stats
}

// HealthCheck returns the health status of all protocol analyzers
func (r *Registry) HealthCheck() map[string]HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]HealthStatus)
	for name, protocol := range r.protocols {
		if r.configs[name].Enabled {
			result[name] = protocol.HealthCheck()
		}
	}
	return result
}

// Shutdown gracefully shuts down all protocol analyzers
func (r *Registry) Shutdown(ctx context.Context) error {
	logger.Info("Shutting down protocol registry")

	r.mu.Lock()
	defer r.mu.Unlock()

	var errors []error
	for name, protocol := range r.protocols {
		if err := protocol.Shutdown(ctx); err != nil {
			errors = append(errors, fmt.Errorf("protocol %s: %w", name, err))
		}
	}

	// Clear all protocols
	r.protocols = make(map[string]Protocol)
	r.configs = make(map[string]Config)
	r.infos = make(map[string]Info)
	r.protocolMap = make(map[string][]string)

	r.stats.TotalProtocols.Store(0)
	r.stats.ActiveProtocols.Store(0)

	logger.Info("Protocol registry shutdown complete")

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}
	return nil
}

// Helper functions

func (r *Registry) handleAnalyzerError(analyzerName, operation string, err error) {
	r.stats.ErrorCount.Add(1)
	r.stats.LastError.Store(err.Error())
	r.stats.LastErrorTime.Store(time.Now().Unix())

	logger.Error("Protocol analyzer error", "analyzer", analyzerName, "operation", operation, "error", err)
}

// Global registry instance
var (
	globalRegistry *Registry
	registryOnce   sync.Once
)

// GetRegistry returns the global protocol registry.
//
// The registry is initialized once and shared across the application.
// Protocol analyzers should register themselves in init() functions using this registry.
func GetRegistry() *Registry {
	registryOnce.Do(func() {
		globalRegistry = newRegistry()
		globalRegistry.Enable()
	})
	return globalRegistry
}
