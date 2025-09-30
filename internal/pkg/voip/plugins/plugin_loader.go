package plugins

import (
	"context"
	"fmt"
	"path/filepath"
	"plugin"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// PluginLoader manages dynamic loading and registration of plugins
type PluginLoader struct {
	registry     *PluginRegistry
	pluginPaths  []string
	loadedPaths  map[string]bool
	factories    map[string]PluginFactory
	mu           sync.RWMutex
	watchEnabled bool
}

// NewPluginLoader creates a new plugin loader
func NewPluginLoader(registry *PluginRegistry) *PluginLoader {
	return &PluginLoader{
		registry:    registry,
		pluginPaths: make([]string, 0),
		loadedPaths: make(map[string]bool),
		factories:   make(map[string]PluginFactory),
	}
}

// AddPluginPath adds a path to search for plugins
func (pl *PluginLoader) AddPluginPath(path string) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	pl.pluginPaths = append(pl.pluginPaths, path)
}

// LoadBuiltinPlugins loads and registers built-in plugins
func (pl *PluginLoader) LoadBuiltinPlugins() error {
	logger.Info("Loading built-in plugins")

	// Register SIP plugin
	sipFactory := &SIPPluginFactory{}
	if err := pl.registerFactory("sip", sipFactory); err != nil {
		return fmt.Errorf("failed to register SIP plugin: %w", err)
	}

	// Register RTP plugin
	rtpFactory := &RTPPluginFactory{}
	if err := pl.registerFactory("rtp", rtpFactory); err != nil {
		return fmt.Errorf("failed to register RTP plugin: %w", err)
	}

	// Register Generic plugin
	genericFactory := &GenericPluginFactory{}
	if err := pl.registerFactory("generic", genericFactory); err != nil {
		return fmt.Errorf("failed to register Generic plugin: %w", err)
	}

	logger.Info("Built-in plugins loaded successfully",
		"sip_enabled", true,
		"rtp_enabled", true,
		"generic_enabled", true)

	return nil
}

// LoadDynamicPlugins loads plugins from specified paths
func (pl *PluginLoader) LoadDynamicPlugins() error {
	pl.mu.RLock()
	paths := make([]string, len(pl.pluginPaths))
	copy(paths, pl.pluginPaths)
	pl.mu.RUnlock()

	if len(paths) == 0 {
		logger.Debug("No plugin paths configured for dynamic loading")
		return nil
	}

	logger.Info("Loading dynamic plugins", "paths", paths)

	for _, path := range paths {
		if err := pl.loadPluginsFromPath(path); err != nil {
			logger.Error("Failed to load plugins from path",
				"path", path,
				"error", err)
			// Continue loading other paths on error
		}
	}

	return nil
}

// loadPluginsFromPath loads all plugins from a specific path
func (pl *PluginLoader) loadPluginsFromPath(path string) error {
	// Find all .so files in the path
	soFiles, err := filepath.Glob(filepath.Join(path, "*.so"))
	if err != nil {
		return fmt.Errorf("failed to find plugin files: %w", err)
	}

	for _, soFile := range soFiles {
		if err := pl.loadPluginFile(soFile); err != nil {
			logger.Error("Failed to load plugin file",
				"file", soFile,
				"error", err)
			// Continue loading other files on error
		}
	}

	return nil
}

// loadPluginFile loads a single plugin file
func (pl *PluginLoader) loadPluginFile(filepath string) error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	// Check if already loaded
	if pl.loadedPaths[filepath] {
		logger.Debug("Plugin file already loaded", "file", filepath)
		return nil
	}

	// Load the plugin
	p, err := plugin.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open plugin file: %w", err)
	}

	// Look for the required symbols
	factorySymbol, err := p.Lookup("PluginFactory")
	if err != nil {
		return fmt.Errorf("plugin missing PluginFactory symbol: %w", err)
	}

	factory, ok := factorySymbol.(PluginFactory)
	if !ok {
		return fmt.Errorf("PluginFactory has incorrect type")
	}

	// Get plugin info
	info := factory.PluginInfo()
	pluginName := sanitizePluginName(info.Name)

	// Register the factory
	pl.factories[pluginName] = factory
	pl.loadedPaths[filepath] = true

	logger.Info("Dynamic plugin loaded successfully",
		"file", filepath,
		"name", info.Name,
		"version", info.Version,
		"protocols", info.Protocols)

	// Create and register plugin instance
	pluginInstance := factory.CreatePlugin()
	if err := pl.registry.RegisterPlugin(pluginName, pluginInstance, info.Config); err != nil {
		return fmt.Errorf("failed to register plugin instance: %w", err)
	}

	return nil
}

// registerFactory registers a built-in plugin factory
func (pl *PluginLoader) registerFactory(name string, factory PluginFactory) error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	pl.factories[name] = factory

	// Create and register plugin instance
	pluginInstance := factory.CreatePlugin()
	info := factory.PluginInfo()

	if err := pl.registry.RegisterPlugin(name, pluginInstance, info.Config); err != nil {
		return fmt.Errorf("failed to register plugin instance: %w", err)
	}

	return nil
}

// ReloadPlugin reloads a specific plugin
func (pl *PluginLoader) ReloadPlugin(name string) error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	factory, exists := pl.factories[name]
	if !exists {
		return fmt.Errorf("plugin factory not found: %s", name)
	}

	// Unregister existing plugin
	if err := pl.registry.UnregisterPlugin(name); err != nil {
		logger.Error("Failed to unregister plugin for reload",
			"name", name,
			"error", err)
	}

	// Create new instance
	pluginInstance := factory.CreatePlugin()
	info := factory.PluginInfo()

	// Register new instance
	if err := pl.registry.RegisterPlugin(name, pluginInstance, info.Config); err != nil {
		return fmt.Errorf("failed to register reloaded plugin: %w", err)
	}

	logger.Info("Plugin reloaded successfully", "name", name)
	return nil
}

// UnloadPlugin unloads a specific plugin
func (pl *PluginLoader) UnloadPlugin(name string) error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	// Unregister from registry
	if err := pl.registry.UnregisterPlugin(name); err != nil {
		return fmt.Errorf("failed to unregister plugin: %w", err)
	}

	// Remove from our tracking
	delete(pl.factories, name)

	logger.Info("Plugin unloaded successfully", "name", name)
	return nil
}

// ListLoadedPlugins returns information about all loaded plugins
func (pl *PluginLoader) ListLoadedPlugins() map[string]PluginInfo {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	result := make(map[string]PluginInfo)
	for name, factory := range pl.factories {
		result[name] = factory.PluginInfo()
	}

	return result
}

// EnablePluginWatch enables automatic plugin reloading on file changes
func (pl *PluginLoader) EnablePluginWatch(ctx context.Context) {
	pl.mu.Lock()
	if pl.watchEnabled {
		pl.mu.Unlock()
		return
	}
	pl.watchEnabled = true
	pl.mu.Unlock()

	go pl.pluginWatcher(ctx)
	logger.Info("Plugin file watching enabled")
}

// pluginWatcher monitors plugin files for changes
func (pl *PluginLoader) pluginWatcher(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Plugin watcher shutting down")
			return
		case <-ticker.C:
			pl.checkForPluginChanges()
		}
	}
}

// checkForPluginChanges checks for new or modified plugin files
func (pl *PluginLoader) checkForPluginChanges() {
	pl.mu.RLock()
	paths := make([]string, len(pl.pluginPaths))
	copy(paths, pl.pluginPaths)
	pl.mu.RUnlock()

	for _, path := range paths {
		soFiles, err := filepath.Glob(filepath.Join(path, "*.so"))
		if err != nil {
			logger.Error("Failed to scan for plugin changes",
				"path", path,
				"error", err)
			continue
		}

		for _, soFile := range soFiles {
			pl.mu.RLock()
			loaded := pl.loadedPaths[soFile]
			pl.mu.RUnlock()

			if !loaded {
				logger.Info("New plugin file detected", "file", soFile)
				if err := pl.loadPluginFile(soFile); err != nil {
					logger.Error("Failed to load new plugin file",
						"file", soFile,
						"error", err)
				}
			}
		}
	}
}

// GetPluginConfig returns configuration for a specific plugin
func (pl *PluginLoader) GetPluginConfig(name string) (PluginConfig, error) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	factory, exists := pl.factories[name]
	if !exists {
		return PluginConfig{}, fmt.Errorf("plugin not found: %s", name)
	}

	return factory.PluginInfo().Config, nil
}

// UpdatePluginConfig updates configuration for a specific plugin
func (pl *PluginLoader) UpdatePluginConfig(name string, config PluginConfig) error {
	// Note: This would require plugins to support dynamic configuration updates
	// For now, we'll reload the plugin with new configuration
	return pl.ReloadPlugin(name)
}

// Shutdown gracefully shuts down the plugin loader
func (pl *PluginLoader) Shutdown(ctx context.Context) error {
	pl.mu.Lock()
	pl.watchEnabled = false
	pl.mu.Unlock()

	logger.Info("Plugin loader shutdown complete")
	return nil
}

// GetPluginStats returns statistics about loaded plugins
func (pl *PluginLoader) GetPluginStats() map[string]interface{} {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	stats := map[string]interface{}{
		"total_factories":   len(pl.factories),
		"loaded_paths":      len(pl.loadedPaths),
		"watch_enabled":     pl.watchEnabled,
		"plugin_paths":      len(pl.pluginPaths),
	}

	// Add per-plugin statistics
	pluginStats := make(map[string]interface{})
	for name := range pl.factories {
		if pluginInfo := pl.registry.ListPlugins(); pluginInfo != nil {
			if info, exists := pluginInfo[name]; exists {
				pluginStats[name] = map[string]interface{}{
					"version":    info.Version,
					"protocols":  info.Protocols,
					"load_time":  info.LoadTime,
					"enabled":    info.Config.Enabled,
				}
			}
		}
	}
	stats["plugins"] = pluginStats

	return stats
}

// sanitizePluginName cleans up plugin names for safe use as identifiers
func sanitizePluginName(name string) string {
	// Convert to lowercase and replace spaces/special chars with underscores
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")

	// Remove any remaining special characters
	result := ""
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			result += string(r)
		}
	}

	return result
}

// Global plugin loader instance
var (
	globalPluginLoader *PluginLoader
	pluginLoaderOnce   sync.Once
)

// GetGlobalPluginLoader returns the global plugin loader instance
func GetGlobalPluginLoader() *PluginLoader {
	pluginLoaderOnce.Do(func() {
		globalPluginLoader = NewPluginLoader(GetGlobalRegistry())
	})
	return globalPluginLoader
}

// InitializePluginSystem initializes the complete plugin system
func InitializePluginSystem() error {
	logger.Info("Initializing plugin system")

	registry := GetGlobalRegistry()
	loader := GetGlobalPluginLoader()

	// Enable the registry
	registry.Enable()

	// Load built-in plugins
	if err := loader.LoadBuiltinPlugins(); err != nil {
		return fmt.Errorf("failed to load built-in plugins: %w", err)
	}

	// Optionally load dynamic plugins if paths are configured
	if err := loader.LoadDynamicPlugins(); err != nil {
		logger.Error("Failed to load dynamic plugins", "error", err)
		// Don't fail initialization if dynamic plugins fail
	}

	logger.Info("Plugin system initialization complete",
		"registry_enabled", registry.IsEnabled(),
		"plugins_loaded", len(registry.ListPlugins()))

	return nil
}

// ShutdownPluginSystem gracefully shuts down the plugin system
func ShutdownPluginSystem(ctx context.Context) error {
	logger.Info("Shutting down plugin system")

	loader := GetGlobalPluginLoader()
	registry := GetGlobalRegistry()

	// Shutdown loader first
	if err := loader.Shutdown(ctx); err != nil {
		logger.Error("Plugin loader shutdown error", "error", err)
	}

	// Shutdown registry
	if err := registry.Shutdown(ctx); err != nil {
		logger.Error("Plugin registry shutdown error", "error", err)
	}

	logger.Info("Plugin system shutdown complete")
	return nil
}