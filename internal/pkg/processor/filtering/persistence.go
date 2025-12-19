package filtering

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// YAMLPersistence implements PersistenceHandler using YAML files
type YAMLPersistence struct{}

// NewYAMLPersistence creates a new YAML persistence handler
func NewYAMLPersistence() *YAMLPersistence {
	return &YAMLPersistence{}
}

// Load loads filters from YAML file
func (yp *YAMLPersistence) Load(filterFile string) (map[string]*management.Filter, error) {
	if filterFile == "" {
		filterFile = filtering.GetDefaultFilterFilePath()
	}

	logger.Info("Loading filters from file", "path", filterFile)

	filters, parseErrors, err := filtering.ParseFileWithErrors(filterFile)
	if err != nil {
		return nil, err
	}

	// Log any parse errors
	for _, parseErr := range parseErrors {
		logger.Warn("Skipping invalid filter", "error", parseErr)
	}

	if len(filters) == 0 && parseErrors == nil {
		logger.Info("Filter file does not exist, starting with empty filter list", "path", filterFile)
	} else {
		logger.Info("Filters loaded successfully", "count", len(filters), "path", filterFile)
	}

	return filters, nil
}

// Save saves filters to YAML file with atomic write
func (yp *YAMLPersistence) Save(filterFile string, filters map[string]*management.Filter) error {
	if filterFile == "" {
		filterFile = filtering.GetDefaultFilterFilePath()
	}

	logger.Debug("Saving filters to file", "path", filterFile)

	if err := filtering.WriteFile(filterFile, filters); err != nil {
		return err
	}

	logger.Debug("Filters saved successfully", "count", len(filters), "path", filterFile)
	return nil
}
