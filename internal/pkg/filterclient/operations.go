package filterclient

import (
	"fmt"

	"github.com/endorses/lippycat/api/gen/management"
)

// ListOptions configures filter listing behavior
type ListOptions struct {
	// HunterID filters results to a specific hunter (empty = all filters)
	HunterID string
}

// List retrieves all filters from the processor
func (c *FilterClient) List(opts ListOptions) ([]*management.Filter, error) {
	ctx, cancel := c.context()
	defer cancel()

	// Use GetFilters RPC - works for both direct and targeted queries
	req := &management.FilterRequest{
		HunterId: opts.HunterID,
	}

	resp, err := c.client.GetFilters(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list filters: %w", err)
	}

	return resp.Filters, nil
}

// Get retrieves a single filter by ID
func (c *FilterClient) Get(id string) (*management.Filter, error) {
	if id == "" {
		return nil, fmt.Errorf("filter ID is required")
	}

	// List all filters and find the one with matching ID
	filters, err := c.List(ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, f := range filters {
		if f.Id == id {
			return f, nil
		}
	}

	return nil, &NotFoundError{ID: id}
}

// Set creates or updates a filter (upsert)
func (c *FilterClient) Set(filter *management.Filter) (*management.FilterUpdateResult, error) {
	if filter == nil {
		return nil, fmt.Errorf("filter is required")
	}
	if filter.Id == "" {
		return nil, fmt.Errorf("filter ID is required")
	}

	ctx, cancel := c.context()
	defer cancel()

	result, err := c.client.UpdateFilter(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to set filter: %w", err)
	}

	return result, nil
}

// Delete removes a filter by ID
func (c *FilterClient) Delete(id string) (*management.FilterUpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("filter ID is required")
	}

	ctx, cancel := c.context()
	defer cancel()

	req := &management.FilterDeleteRequest{
		FilterId: id,
	}

	result, err := c.client.DeleteFilter(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to delete filter: %w", err)
	}

	return result, nil
}

// NotFoundError indicates a filter was not found
type NotFoundError struct {
	ID string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("filter not found: %s", e.ID)
}

// IsNotFound returns true if the error is a NotFoundError
func IsNotFound(err error) bool {
	_, ok := err.(*NotFoundError)
	return ok
}
