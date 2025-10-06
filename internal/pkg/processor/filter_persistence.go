package processor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"gopkg.in/yaml.v3"
)

// FilterConfig represents the YAML structure for filter persistence
type FilterConfig struct {
	Filters []*FilterYAML `yaml:"filters"`
}

// FilterYAML represents a filter in YAML format
type FilterYAML struct {
	ID            string   `yaml:"id"`
	Type          string   `yaml:"type"`
	Pattern       string   `yaml:"pattern"`
	TargetHunters []string `yaml:"target_hunters,omitempty"`
	Enabled       bool     `yaml:"enabled"`
	Description   string   `yaml:"description,omitempty"`
}

var (
	// File lock for atomic writes
	filterFileLock sync.Mutex
)

// getDefaultFilterFilePath returns the default path for filter persistence
func getDefaultFilterFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "filters.yaml" // Fallback to local directory
	}
	return filepath.Join(homeDir, ".config", "lippycat", "filters.yaml")
}

// loadFilters loads filters from YAML file
func (p *Processor) loadFilters() error {
	filterFile := p.config.FilterFile
	if filterFile == "" {
		filterFile = getDefaultFilterFilePath()
	}

	logger.Info("Loading filters from file", "path", filterFile)

	// Check if file exists
	if _, err := os.Stat(filterFile); os.IsNotExist(err) {
		logger.Info("Filter file does not exist, starting with empty filter list", "path", filterFile)
		return nil
	}

	// Read file
	data, err := os.ReadFile(filterFile)
	if err != nil {
		return fmt.Errorf("failed to read filter file: %w", err)
	}

	// Parse YAML
	var config FilterConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse filter YAML: %w", err)
	}

	// Convert to protobuf filters and populate map
	p.filtersMu.Lock()
	defer p.filtersMu.Unlock()

	loadedCount := 0
	for _, filterYAML := range config.Filters {
		filter, err := yamlToProtoFilter(filterYAML)
		if err != nil {
			logger.Warn("Skipping invalid filter", "id", filterYAML.ID, "error", err)
			continue
		}
		p.filters[filter.Id] = filter
		loadedCount++
	}

	logger.Info("Filters loaded successfully", "count", loadedCount, "path", filterFile)
	return nil
}

// saveFilters saves filters to YAML file with atomic write
func (p *Processor) saveFilters() error {
	filterFile := p.config.FilterFile
	if filterFile == "" {
		filterFile = getDefaultFilterFilePath()
	}

	logger.Debug("Saving filters to file", "path", filterFile)

	// Lock for atomic write
	filterFileLock.Lock()
	defer filterFileLock.Unlock()

	// Create directory if it doesn't exist
	dir := filepath.Dir(filterFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create filter directory: %w", err)
	}

	// Convert filters to YAML format
	p.filtersMu.RLock()
	config := FilterConfig{
		Filters: make([]*FilterYAML, 0, len(p.filters)),
	}
	for _, filter := range p.filters {
		config.Filters = append(config.Filters, protoToYAMLFilter(filter))
	}
	p.filtersMu.RUnlock()

	// Marshal to YAML
	data, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal filters to YAML: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tempFile := filterFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp filter file: %w", err)
	}

	if err := os.Rename(tempFile, filterFile); err != nil {
		os.Remove(tempFile) // Cleanup temp file on error
		return fmt.Errorf("failed to rename temp filter file: %w", err)
	}

	logger.Debug("Filters saved successfully", "count", len(config.Filters), "path", filterFile)
	return nil
}

// yamlToProtoFilter converts YAML filter to protobuf filter
func yamlToProtoFilter(yaml *FilterYAML) (*management.Filter, error) {
	if yaml.ID == "" {
		return nil, fmt.Errorf("filter ID is required")
	}
	if yaml.Pattern == "" {
		return nil, fmt.Errorf("filter pattern is required")
	}

	// Parse filter type
	filterType, err := parseFilterType(yaml.Type)
	if err != nil {
		return nil, err
	}

	return &management.Filter{
		Id:            yaml.ID,
		Type:          filterType,
		Pattern:       yaml.Pattern,
		TargetHunters: yaml.TargetHunters,
		Enabled:       yaml.Enabled,
		Description:   yaml.Description,
	}, nil
}

// protoToYAMLFilter converts protobuf filter to YAML filter
func protoToYAMLFilter(proto *management.Filter) *FilterYAML {
	return &FilterYAML{
		ID:            proto.Id,
		Type:          filterTypeToString(proto.Type),
		Pattern:       proto.Pattern,
		TargetHunters: proto.TargetHunters,
		Enabled:       proto.Enabled,
		Description:   proto.Description,
	}
}

// parseFilterType converts string to FilterType enum
func parseFilterType(typeStr string) (management.FilterType, error) {
	switch typeStr {
	case "FILTER_SIP_USER", "sip_user":
		return management.FilterType_FILTER_SIP_USER, nil
	case "FILTER_PHONE_NUMBER", "phone_number":
		return management.FilterType_FILTER_PHONE_NUMBER, nil
	case "FILTER_IP_ADDRESS", "ip_address":
		return management.FilterType_FILTER_IP_ADDRESS, nil
	case "FILTER_CALL_ID", "call_id":
		return management.FilterType_FILTER_CALL_ID, nil
	case "FILTER_CODEC", "codec":
		return management.FilterType_FILTER_CODEC, nil
	case "FILTER_BPF", "bpf":
		return management.FilterType_FILTER_BPF, nil
	default:
		return 0, fmt.Errorf("unknown filter type: %s", typeStr)
	}
}

// filterTypeToString converts FilterType enum to string
func filterTypeToString(filterType management.FilterType) string {
	switch filterType {
	case management.FilterType_FILTER_SIP_USER:
		return "sip_user"
	case management.FilterType_FILTER_PHONE_NUMBER:
		return "phone_number"
	case management.FilterType_FILTER_IP_ADDRESS:
		return "ip_address"
	case management.FilterType_FILTER_CALL_ID:
		return "call_id"
	case management.FilterType_FILTER_CODEC:
		return "codec"
	case management.FilterType_FILTER_BPF:
		return "bpf"
	default:
		return "unknown"
	}
}
