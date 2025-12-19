package filterclient

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/api/gen/management"
)

func TestFilterClient_List(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filters, err := client.List(ListOptions{})
		require.NoError(t, err)
		assert.Empty(t, filters)
	})

	t.Run("with filters", func(t *testing.T) {
		mock := newMockServer()
		mock.filters = []*management.Filter{
			{
				Id:      "filter-1",
				Type:    management.FilterType_FILTER_SIP_USER,
				Pattern: "alice",
				Enabled: true,
			},
			{
				Id:      "filter-2",
				Type:    management.FilterType_FILTER_IP_ADDRESS,
				Pattern: "192.168.1.0/24",
				Enabled: true,
			},
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filters, err := client.List(ListOptions{})
		require.NoError(t, err)
		assert.Len(t, filters, 2)
		assert.Equal(t, "filter-1", filters[0].Id)
		assert.Equal(t, "filter-2", filters[1].Id)
	})

	t.Run("error from server", func(t *testing.T) {
		mock := newMockServer()
		mock.getFiltersErr = fmt.Errorf("server error")

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		_, err := client.List(ListOptions{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list filters")
	})
}

func TestFilterClient_Get(t *testing.T) {
	t.Run("filter found", func(t *testing.T) {
		mock := newMockServer()
		mock.filters = []*management.Filter{
			{
				Id:          "filter-1",
				Type:        management.FilterType_FILTER_SIP_USER,
				Pattern:     "alice",
				Enabled:     true,
				Description: "Test filter",
			},
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filter, err := client.Get("filter-1")
		require.NoError(t, err)
		assert.Equal(t, "filter-1", filter.Id)
		assert.Equal(t, "alice", filter.Pattern)
		assert.Equal(t, "Test filter", filter.Description)
	})

	t.Run("filter not found", func(t *testing.T) {
		mock := newMockServer()
		mock.filters = []*management.Filter{
			{Id: "filter-1", Pattern: "alice"},
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		_, err := client.Get("nonexistent")
		assert.Error(t, err)
		assert.True(t, IsNotFound(err))

		notFoundErr, ok := err.(*NotFoundError)
		require.True(t, ok)
		assert.Equal(t, "nonexistent", notFoundErr.ID)
	})

	t.Run("empty id", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		_, err := client.Get("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "filter ID is required")
	})
}

func TestFilterClient_Set(t *testing.T) {
	t.Run("create new filter", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filter := &management.Filter{
			Id:      "new-filter",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "bob",
			Enabled: true,
		}

		result, err := client.Set(filter)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, uint32(1), result.HuntersUpdated)

		// Verify filter was added
		assert.Len(t, mock.filters, 1)
		assert.Equal(t, "new-filter", mock.filters[0].Id)
	})

	t.Run("update existing filter", func(t *testing.T) {
		mock := newMockServer()
		mock.filters = []*management.Filter{
			{
				Id:      "existing",
				Type:    management.FilterType_FILTER_SIP_USER,
				Pattern: "old-pattern",
				Enabled: true,
			},
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filter := &management.Filter{
			Id:      "existing",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "new-pattern",
			Enabled: true,
		}

		result, err := client.Set(filter)
		require.NoError(t, err)
		assert.True(t, result.Success)

		// Verify filter was updated
		assert.Len(t, mock.filters, 1)
		assert.Equal(t, "new-pattern", mock.filters[0].Pattern)
	})

	t.Run("nil filter", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		_, err := client.Set(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "filter is required")
	})

	t.Run("empty id", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filter := &management.Filter{
			Pattern: "test",
		}

		_, err := client.Set(filter)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "filter ID is required")
	})

	t.Run("server error", func(t *testing.T) {
		mock := newMockServer()
		mock.updateFilterErr = fmt.Errorf("server error")

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filter := &management.Filter{
			Id:      "test",
			Pattern: "test",
		}

		_, err := client.Set(filter)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set filter")
	})
}

func TestFilterClient_Delete(t *testing.T) {
	t.Run("delete existing filter", func(t *testing.T) {
		mock := newMockServer()
		mock.filters = []*management.Filter{
			{Id: "filter-1", Pattern: "alice"},
			{Id: "filter-2", Pattern: "bob"},
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		result, err := client.Delete("filter-1")
		require.NoError(t, err)
		assert.True(t, result.Success)

		// Verify filter was removed
		assert.Len(t, mock.filters, 1)
		assert.Equal(t, "filter-2", mock.filters[0].Id)
	})

	t.Run("empty id", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		_, err := client.Delete("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "filter ID is required")
	})

	t.Run("server error", func(t *testing.T) {
		mock := newMockServer()
		mock.deleteFilterErr = fmt.Errorf("server error")

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		_, err := client.Delete("filter-1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete filter")
	})
}

func TestNotFoundError(t *testing.T) {
	err := &NotFoundError{ID: "test-id"}
	assert.Equal(t, "filter not found: test-id", err.Error())
	assert.True(t, IsNotFound(err))
	assert.False(t, IsNotFound(fmt.Errorf("other error")))
}
