package filtering

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"gopkg.in/yaml.v3"
)

var (
	// fileLock protects atomic file writes
	fileLock sync.Mutex
)

// ParseFile reads and parses a YAML filter file, returning protobuf filters
func ParseFile(path string) (map[string]*management.Filter, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return make(map[string]*management.Filter), nil
	}

	// Read file
	// #nosec G304 -- Path is from configuration, not user input
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read filter file: %w", err)
	}

	// Parse YAML
	var config FilterConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse filter YAML: %w", err)
	}

	// Convert to protobuf filters and populate map
	filters := make(map[string]*management.Filter)
	for _, filterYAML := range config.Filters {
		filter, err := YAMLToProto(filterYAML)
		if err != nil {
			// Skip invalid filters with a warning (caller should log)
			continue
		}
		filters[filter.Id] = filter
	}

	return filters, nil
}

// ParseFileWithErrors reads and parses a YAML filter file, returning both
// valid filters and any parse errors encountered
func ParseFileWithErrors(path string) (map[string]*management.Filter, []error, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return make(map[string]*management.Filter), nil, nil
	}

	// Read file
	// #nosec G304 -- Path is from configuration, not user input
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read filter file: %w", err)
	}

	// Parse YAML
	var config FilterConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to parse filter YAML: %w", err)
	}

	// Convert to protobuf filters and collect errors
	filters := make(map[string]*management.Filter)
	var parseErrors []error
	for _, filterYAML := range config.Filters {
		filter, err := YAMLToProto(filterYAML)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("filter %q: %w", filterYAML.ID, err))
			continue
		}
		filters[filter.Id] = filter
	}

	return filters, parseErrors, nil
}

// WriteFile writes filters to a YAML file with atomic write
func WriteFile(path string, filters map[string]*management.Filter) error {
	fileLock.Lock()
	defer fileLock.Unlock()

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create filter directory: %w", err)
	}

	// Convert filters to YAML format
	config := FilterConfig{
		Filters: make([]*FilterYAML, 0, len(filters)),
	}
	for _, filter := range filters {
		config.Filters = append(config.Filters, ProtoToYAML(filter))
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal filters to YAML: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp filter file: %w", err)
	}

	if err := os.Rename(tempFile, path); err != nil {
		_ = os.Remove(tempFile) // Cleanup temp file on error
		return fmt.Errorf("failed to rename temp filter file: %w", err)
	}

	return nil
}

// GetDefaultFilterFilePath returns the default path for filter persistence
func GetDefaultFilterFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "filters.yaml" // Fallback to local directory
	}
	return filepath.Join(homeDir, ".config", "lippycat", "filters.yaml")
}
