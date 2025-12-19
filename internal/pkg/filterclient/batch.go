package filterclient

import (
	"fmt"

	"github.com/endorses/lippycat/api/gen/management"
)

// BatchResult contains results of a batch operation
type BatchResult struct {
	// Succeeded contains IDs of filters that were successfully processed
	Succeeded []string

	// Failed contains errors for filters that failed
	Failed []BatchError

	// TotalHuntersUpdated is the sum of hunters updated across all operations
	TotalHuntersUpdated uint32
}

// BatchError represents a failure for a single item in a batch operation
type BatchError struct {
	// ID of the filter that failed
	ID string

	// Error message
	Error string
}

// HasErrors returns true if any operations in the batch failed
func (r *BatchResult) HasErrors() bool {
	return len(r.Failed) > 0
}

// Summary returns a summary of the batch operation
func (r *BatchResult) Summary() string {
	if len(r.Failed) == 0 {
		return fmt.Sprintf("all %d operations succeeded, %d hunters updated",
			len(r.Succeeded), r.TotalHuntersUpdated)
	}
	return fmt.Sprintf("%d succeeded, %d failed, %d hunters updated",
		len(r.Succeeded), len(r.Failed), r.TotalHuntersUpdated)
}

// SetBatch creates or updates multiple filters
// Operations are best-effort - failures for individual filters don't stop the batch
func (c *FilterClient) SetBatch(filters []*management.Filter) (*BatchResult, error) {
	if len(filters) == 0 {
		return &BatchResult{}, nil
	}

	result := &BatchResult{
		Succeeded: make([]string, 0, len(filters)),
		Failed:    make([]BatchError, 0),
	}

	for _, filter := range filters {
		if filter.Id == "" {
			result.Failed = append(result.Failed, BatchError{
				ID:    "(empty)",
				Error: "filter ID is required",
			})
			continue
		}

		updateResult, err := c.Set(filter)
		if err != nil {
			result.Failed = append(result.Failed, BatchError{
				ID:    filter.Id,
				Error: err.Error(),
			})
			continue
		}

		if !updateResult.Success {
			result.Failed = append(result.Failed, BatchError{
				ID:    filter.Id,
				Error: updateResult.Error,
			})
			continue
		}

		result.Succeeded = append(result.Succeeded, filter.Id)
		result.TotalHuntersUpdated += updateResult.HuntersUpdated
	}

	return result, nil
}

// DeleteBatch removes multiple filters by ID
// Operations are best-effort - failures for individual filters don't stop the batch
func (c *FilterClient) DeleteBatch(ids []string) (*BatchResult, error) {
	if len(ids) == 0 {
		return &BatchResult{}, nil
	}

	result := &BatchResult{
		Succeeded: make([]string, 0, len(ids)),
		Failed:    make([]BatchError, 0),
	}

	for _, id := range ids {
		if id == "" {
			result.Failed = append(result.Failed, BatchError{
				ID:    "(empty)",
				Error: "filter ID is required",
			})
			continue
		}

		deleteResult, err := c.Delete(id)
		if err != nil {
			result.Failed = append(result.Failed, BatchError{
				ID:    id,
				Error: err.Error(),
			})
			continue
		}

		if !deleteResult.Success {
			result.Failed = append(result.Failed, BatchError{
				ID:    id,
				Error: deleteResult.Error,
			})
			continue
		}

		result.Succeeded = append(result.Succeeded, id)
		result.TotalHuntersUpdated += deleteResult.HuntersUpdated
	}

	return result, nil
}
