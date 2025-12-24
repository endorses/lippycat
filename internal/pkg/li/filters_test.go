package li

import (
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/api/gen/management"
)

// mockFilterPusher records filter operations for testing.
type mockFilterPusher struct {
	mu       sync.Mutex
	updates  []*management.Filter
	deletes  []string
	failNext bool
}

func (m *mockFilterPusher) UpdateFilter(filter *management.Filter) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext {
		m.failNext = false
		return assert.AnError
	}
	m.updates = append(m.updates, filter)
	return nil
}

func (m *mockFilterPusher) DeleteFilter(filterID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext {
		m.failNext = false
		return assert.AnError
	}
	m.deletes = append(m.deletes, filterID)
	return nil
}

func (m *mockFilterPusher) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = nil
	m.deletes = nil
}

func TestNewFilterManager(t *testing.T) {
	m := NewFilterManager(nil)
	require.NotNil(t, m)
	assert.Equal(t, 0, m.FilterCount())
	assert.Equal(t, 0, m.TaskCount())
}

func TestFilterManagerCreateFiltersForTask(t *testing.T) {
	pusher := &mockFilterPusher{}
	m := NewFilterManager(pusher)

	t.Run("create filters for task with multiple targets", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
				{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
				{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
			},
			DeliveryType: DeliveryX2andX3,
		}

		filterIDs, err := m.CreateFiltersForTask(task)
		require.NoError(t, err)
		assert.Len(t, filterIDs, 3)

		// Verify filters were created
		assert.Equal(t, 3, m.FilterCount())
		assert.Equal(t, 1, m.TaskCount())

		// Verify pusher received updates
		assert.Len(t, pusher.updates, 3)

		// Verify XID mapping
		for _, id := range filterIDs {
			xid, exists := m.GetXIDForFilter(id)
			assert.True(t, exists)
			assert.Equal(t, task.XID, xid)
		}

		// Verify filters are retrievable
		storedIDs := m.GetFiltersForXID(task.XID)
		assert.ElementsMatch(t, filterIDs, storedIDs)
	})

	t.Run("create filters for nil task", func(t *testing.T) {
		_, err := m.CreateFiltersForTask(nil)
		require.Error(t, err)
	})

	t.Run("create filters for task without targets", func(t *testing.T) {
		task := &InterceptTask{
			XID:          uuid.New(),
			Targets:      []TargetIdentity{},
			DeliveryType: DeliveryX2Only,
		}
		_, err := m.CreateFiltersForTask(task)
		require.Error(t, err)
	})

	t.Run("duplicate task fails", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:bob@example.com"},
			},
			DeliveryType: DeliveryX2Only,
		}

		_, err := m.CreateFiltersForTask(task)
		require.NoError(t, err)

		// Try to create again
		_, err = m.CreateFiltersForTask(task)
		require.Error(t, err)
	})
}

func TestFilterManagerTargetTypeMapping(t *testing.T) {
	m := NewFilterManager(nil)

	testCases := []struct {
		name         string
		target       TargetIdentity
		expectedType management.FilterType
		expectedPat  string
	}{
		{
			name:         "SIPURI",
			target:       TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			expectedType: management.FilterType_FILTER_SIP_URI,
			expectedPat:  "alice@example.com",
		},
		{
			name:         "SIPURI with sips",
			target:       TargetIdentity{Type: TargetTypeSIPURI, Value: "sips:secure@example.com"},
			expectedType: management.FilterType_FILTER_SIP_URI,
			expectedPat:  "secure@example.com",
		},
		{
			name:         "SIPURI with params",
			target:       TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:alice@example.com;transport=tcp"},
			expectedType: management.FilterType_FILTER_SIP_URI,
			expectedPat:  "alice@example.com",
		},
		{
			name:         "SIPURI with port",
			target:       TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:alice@example.com:5060"},
			expectedType: management.FilterType_FILTER_SIP_URI,
			expectedPat:  "alice@example.com",
		},
		{
			name:         "TELURI",
			target:       TargetIdentity{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
			expectedType: management.FilterType_FILTER_PHONE_NUMBER,
			expectedPat:  "15551234567",
		},
		{
			name:         "TELURI with dashes",
			target:       TargetIdentity{Type: TargetTypeTELURI, Value: "tel:+1-555-123-4567"},
			expectedType: management.FilterType_FILTER_PHONE_NUMBER,
			expectedPat:  "15551234567",
		},
		{
			name:         "NAI",
			target:       TargetIdentity{Type: TargetTypeNAI, Value: "user@realm.example.com"},
			expectedType: management.FilterType_FILTER_SIP_URI,
			expectedPat:  "user@realm.example.com",
		},
		{
			name:         "IPv4Address",
			target:       TargetIdentity{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
			expectedType: management.FilterType_FILTER_IP_ADDRESS,
			expectedPat:  "192.168.1.100",
		},
		{
			name:         "IPv6Address",
			target:       TargetIdentity{Type: TargetTypeIPv6Address, Value: "2001:db8::1"},
			expectedType: management.FilterType_FILTER_IP_ADDRESS,
			expectedPat:  "2001:db8::1",
		},
		{
			name:         "IPv4CIDR",
			target:       TargetIdentity{Type: TargetTypeIPv4CIDR, Value: "10.0.0.0/8"},
			expectedType: management.FilterType_FILTER_IP_ADDRESS,
			expectedPat:  "10.0.0.0/8",
		},
		{
			name:         "IPv6CIDR",
			target:       TargetIdentity{Type: TargetTypeIPv6CIDR, Value: "2001:db8::/32"},
			expectedType: management.FilterType_FILTER_IP_ADDRESS,
			expectedPat:  "2001:db8::/32",
		},
		{
			name:         "Username",
			target:       TargetIdentity{Type: TargetTypeUsername, Value: "alice"},
			expectedType: management.FilterType_FILTER_SIP_USER,
			expectedPat:  "alice",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			task := &InterceptTask{
				XID:          uuid.New(),
				Targets:      []TargetIdentity{tc.target},
				DeliveryType: DeliveryX2Only,
			}

			filterIDs, err := m.CreateFiltersForTask(task)
			require.NoError(t, err)
			require.Len(t, filterIDs, 1)

			filter, exists := m.GetFilter(filterIDs[0])
			require.True(t, exists)
			assert.Equal(t, tc.expectedType, filter.Type)
			assert.Equal(t, tc.expectedPat, filter.Pattern)
			assert.True(t, filter.Enabled)
		})
	}
}

func TestFilterManagerUpdateFiltersForTask(t *testing.T) {
	pusher := &mockFilterPusher{}
	m := NewFilterManager(pusher)

	t.Run("update existing task", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			},
			DeliveryType: DeliveryX2Only,
		}

		// Create initial filters
		initialIDs, err := m.CreateFiltersForTask(task)
		require.NoError(t, err)
		require.Len(t, initialIDs, 1)

		// Get the initial filter pattern
		initialFilter, exists := m.GetFilter(initialIDs[0])
		require.True(t, exists)
		assert.Equal(t, "alice@example.com", initialFilter.Pattern)

		pusher.reset()

		// Update with new targets
		task.Targets = []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:bob@example.com"},
			{Type: TargetTypeIPv4Address, Value: "10.0.0.1"},
		}

		err = m.UpdateFiltersForTask(task)
		require.NoError(t, err)

		// Verify old filter was deleted
		assert.Len(t, pusher.deletes, 1)
		assert.Equal(t, initialIDs[0], pusher.deletes[0])

		// Verify new filters were created
		assert.Len(t, pusher.updates, 2)

		// Verify new filters are stored with updated patterns
		newIDs := m.GetFiltersForXID(task.XID)
		assert.Len(t, newIDs, 2)

		// Verify the first filter now has bob's pattern (not alice's)
		newFilter, exists := m.GetFilter(newIDs[0])
		require.True(t, exists)
		assert.Equal(t, "bob@example.com", newFilter.Pattern)
	})

	t.Run("update nonexistent task creates new", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:new@example.com"},
			},
			DeliveryType: DeliveryX2Only,
		}

		pusher.reset()
		err := m.UpdateFiltersForTask(task)
		require.NoError(t, err)

		assert.Len(t, pusher.updates, 1)
		assert.Equal(t, 1, len(m.GetFiltersForXID(task.XID)))
	})
}

func TestFilterManagerRemoveFiltersForTask(t *testing.T) {
	pusher := &mockFilterPusher{}
	m := NewFilterManager(pusher)

	t.Run("remove existing filters", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
				{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
			},
			DeliveryType: DeliveryX2Only,
		}

		filterIDs, err := m.CreateFiltersForTask(task)
		require.NoError(t, err)
		assert.Len(t, filterIDs, 2)

		pusher.reset()

		err = m.RemoveFiltersForTask(task.XID)
		require.NoError(t, err)

		// Verify filters were deleted
		assert.Len(t, pusher.deletes, 2)
		assert.Equal(t, 0, m.FilterCount())
		assert.Equal(t, 0, m.TaskCount())

		// Verify XID lookup no longer works
		for _, id := range filterIDs {
			_, exists := m.GetXIDForFilter(id)
			assert.False(t, exists)
		}
	})

	t.Run("remove nonexistent task is noop", func(t *testing.T) {
		err := m.RemoveFiltersForTask(uuid.New())
		require.NoError(t, err)
	})
}

func TestFilterManagerLookupMatches(t *testing.T) {
	m := NewFilterManager(nil)

	// Create multiple tasks
	task1 := &InterceptTask{
		XID: uuid.New(),
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DeliveryType: DeliveryX2Only,
	}
	task2 := &InterceptTask{
		XID: uuid.New(),
		Targets: []TargetIdentity{
			{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
		},
		DeliveryType: DeliveryX3Only,
	}

	ids1, err := m.CreateFiltersForTask(task1)
	require.NoError(t, err)
	ids2, err := m.CreateFiltersForTask(task2)
	require.NoError(t, err)

	t.Run("lookup single match", func(t *testing.T) {
		results := m.LookupMatches([]string{ids1[0]})
		assert.Len(t, results, 1)
		assert.Equal(t, task1.XID, results[0].XID)
		assert.Equal(t, ids1[0], results[0].FilterID)
	})

	t.Run("lookup multiple matches", func(t *testing.T) {
		results := m.LookupMatches([]string{ids1[0], ids2[0]})
		assert.Len(t, results, 2)

		xids := make([]uuid.UUID, len(results))
		for i, r := range results {
			xids[i] = r.XID
		}
		assert.Contains(t, xids, task1.XID)
		assert.Contains(t, xids, task2.XID)
	})

	t.Run("lookup with non-LI filter", func(t *testing.T) {
		results := m.LookupMatches([]string{"non-li-filter", ids1[0]})
		assert.Len(t, results, 1)
		assert.Equal(t, task1.XID, results[0].XID)
	})

	t.Run("lookup no matches", func(t *testing.T) {
		results := m.LookupMatches([]string{"non-li-filter-1", "non-li-filter-2"})
		assert.Len(t, results, 0)
	})

	t.Run("deduplication for same task", func(t *testing.T) {
		// Create task with multiple targets
		task3 := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:multi1@example.com"},
				{Type: TargetTypeSIPURI, Value: "sip:multi2@example.com"},
			},
			DeliveryType: DeliveryX2andX3,
		}
		ids3, err := m.CreateFiltersForTask(task3)
		require.NoError(t, err)

		// Both filters match, but should deduplicate
		results := m.LookupMatches(ids3)
		assert.Len(t, results, 1)
		assert.Equal(t, task3.XID, results[0].XID)
	})
}

func TestExtractSIPURIPattern(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"sip:alice@example.com", "alice@example.com"},
		{"sips:alice@example.com", "alice@example.com"},
		{"SIP:alice@example.com", "alice@example.com"},
		{"sip:alice@example.com;transport=tcp", "alice@example.com"},
		{"sip:alice@example.com:5060", "alice@example.com"},
		{"sip:alice@example.com:5060;transport=udp", "alice@example.com"},
		{"alice@example.com", "alice@example.com"}, // Already extracted
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := extractSIPURIPattern(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractPhonePattern(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"tel:+15551234567", "15551234567"},
		{"tel:+1-555-123-4567", "15551234567"},
		{"tel:+49 123 456789", "49123456789"},
		{"+15551234567", "15551234567"},
		{"15551234567", "15551234567"},
		{"tel:+1 (555) 123-4567", "15551234567"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := extractPhonePattern(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFilterManagerConcurrency(t *testing.T) {
	m := NewFilterManager(nil)

	const goroutines = 10
	const tasksPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()

			for i := 0; i < tasksPerGoroutine; i++ {
				task := &InterceptTask{
					XID: uuid.New(),
					Targets: []TargetIdentity{
						{Type: TargetTypeSIPURI, Value: "sip:concurrent@example.com"},
					},
					DeliveryType: DeliveryX2Only,
				}

				ids, err := m.CreateFiltersForTask(task)
				if err != nil {
					t.Errorf("CreateFiltersForTask failed: %v", err)
					return
				}

				// Read operations
				_ = m.GetFiltersForXID(task.XID)
				for _, id := range ids {
					_, _ = m.GetXIDForFilter(id)
					_, _ = m.GetFilter(id)
				}
				_ = m.LookupMatches(ids)

				// Update
				task.Targets = append(task.Targets, TargetIdentity{
					Type:  TargetTypeIPv4Address,
					Value: "10.0.0.1",
				})
				if err := m.UpdateFiltersForTask(task); err != nil {
					t.Errorf("UpdateFiltersForTask failed: %v", err)
					return
				}

				// Remove
				if err := m.RemoveFiltersForTask(task.XID); err != nil {
					t.Errorf("RemoveFiltersForTask failed: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	// All tasks should be cleaned up
	assert.Equal(t, 0, m.FilterCount())
	assert.Equal(t, 0, m.TaskCount())
}
