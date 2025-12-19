package filterclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/api/gen/management"
)

func TestFilterClient_SetBatch(t *testing.T) {
	t.Run("empty batch", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		result, err := client.SetBatch([]*management.Filter{})
		require.NoError(t, err)
		assert.Empty(t, result.Succeeded)
		assert.Empty(t, result.Failed)
		assert.False(t, result.HasErrors())
	})

	t.Run("all succeed", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filters := []*management.Filter{
			{Id: "filter-1", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice"},
			{Id: "filter-2", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.1.0/24"},
			{Id: "filter-3", Type: management.FilterType_FILTER_CALL_ID, Pattern: "call-123"},
		}

		result, err := client.SetBatch(filters)
		require.NoError(t, err)
		assert.Len(t, result.Succeeded, 3)
		assert.Empty(t, result.Failed)
		assert.False(t, result.HasErrors())
		assert.Equal(t, uint32(3), result.TotalHuntersUpdated)

		// Verify all filters were added
		assert.Len(t, mock.filters, 3)
	})

	t.Run("some fail validation", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filters := []*management.Filter{
			{Id: "filter-1", Pattern: "alice"},
			{Id: "", Pattern: "no-id"}, // Empty ID should fail
			{Id: "filter-3", Pattern: "bob"},
		}

		result, err := client.SetBatch(filters)
		require.NoError(t, err)
		assert.Len(t, result.Succeeded, 2)
		assert.Len(t, result.Failed, 1)
		assert.True(t, result.HasErrors())
		assert.Equal(t, "(empty)", result.Failed[0].ID)

		// Verify valid filters were added
		assert.Len(t, mock.filters, 2)
	})

	t.Run("server returns failure", func(t *testing.T) {
		mock := newMockServer()
		mock.updateFilterResp = &management.FilterUpdateResult{
			Success: false,
			Error:   "server rejected filter",
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		filters := []*management.Filter{
			{Id: "filter-1", Pattern: "alice"},
		}

		result, err := client.SetBatch(filters)
		require.NoError(t, err)
		assert.Empty(t, result.Succeeded)
		assert.Len(t, result.Failed, 1)
		assert.Equal(t, "filter-1", result.Failed[0].ID)
		assert.Equal(t, "server rejected filter", result.Failed[0].Error)
	})
}

func TestFilterClient_DeleteBatch(t *testing.T) {
	t.Run("empty batch", func(t *testing.T) {
		mock := newMockServer()
		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		result, err := client.DeleteBatch([]string{})
		require.NoError(t, err)
		assert.Empty(t, result.Succeeded)
		assert.Empty(t, result.Failed)
		assert.False(t, result.HasErrors())
	})

	t.Run("all succeed", func(t *testing.T) {
		mock := newMockServer()
		mock.filters = []*management.Filter{
			{Id: "filter-1", Pattern: "alice"},
			{Id: "filter-2", Pattern: "bob"},
			{Id: "filter-3", Pattern: "carol"},
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		result, err := client.DeleteBatch([]string{"filter-1", "filter-2"})
		require.NoError(t, err)
		assert.Len(t, result.Succeeded, 2)
		assert.Empty(t, result.Failed)
		assert.False(t, result.HasErrors())
		assert.Equal(t, uint32(2), result.TotalHuntersUpdated)

		// Verify filters were removed
		assert.Len(t, mock.filters, 1)
		assert.Equal(t, "filter-3", mock.filters[0].Id)
	})

	t.Run("some fail validation", func(t *testing.T) {
		mock := newMockServer()
		mock.filters = []*management.Filter{
			{Id: "filter-1", Pattern: "alice"},
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		result, err := client.DeleteBatch([]string{"filter-1", "", "filter-3"})
		require.NoError(t, err)
		assert.Len(t, result.Succeeded, 2) // filter-1 and filter-3 (non-existent is still "successful" in mock)
		assert.Len(t, result.Failed, 1)
		assert.True(t, result.HasErrors())
		assert.Equal(t, "(empty)", result.Failed[0].ID)
	})

	t.Run("server returns failure", func(t *testing.T) {
		mock := newMockServer()
		mock.deleteFilterResp = &management.FilterUpdateResult{
			Success: false,
			Error:   "filter in use",
		}

		client, cleanup := createTestClient(t, mock)
		defer cleanup()

		result, err := client.DeleteBatch([]string{"filter-1"})
		require.NoError(t, err)
		assert.Empty(t, result.Succeeded)
		assert.Len(t, result.Failed, 1)
		assert.Equal(t, "filter-1", result.Failed[0].ID)
		assert.Equal(t, "filter in use", result.Failed[0].Error)
	})
}

func TestBatchResult_Summary(t *testing.T) {
	t.Run("all succeed", func(t *testing.T) {
		result := &BatchResult{
			Succeeded:           []string{"a", "b", "c"},
			Failed:              []BatchError{},
			TotalHuntersUpdated: 5,
		}
		assert.Equal(t, "all 3 operations succeeded, 5 hunters updated", result.Summary())
	})

	t.Run("mixed results", func(t *testing.T) {
		result := &BatchResult{
			Succeeded:           []string{"a", "b"},
			Failed:              []BatchError{{ID: "c", Error: "failed"}},
			TotalHuntersUpdated: 3,
		}
		assert.Equal(t, "2 succeeded, 1 failed, 3 hunters updated", result.Summary())
	})
}
