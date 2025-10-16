package filtering

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestManager_AddAndRemoveChannel(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	hunterID := "hunter-1"
	ch := manager.AddChannel(hunterID)
	assert.NotNil(t, ch, "channel should be created")

	// Verify channel is in the map
	manager.channelsMu.RLock()
	_, exists := manager.channels[hunterID]
	manager.channelsMu.RUnlock()
	assert.True(t, exists, "channel should be registered")

	// Remove channel
	manager.RemoveChannel(hunterID)

	// Verify channel is removed and closed
	manager.channelsMu.RLock()
	_, exists = manager.channels[hunterID]
	manager.channelsMu.RUnlock()
	assert.False(t, exists, "channel should be removed")

	// Verify channel is closed
	_, ok := <-ch
	assert.False(t, ok, "channel should be closed")
}

func TestManager_Update_SingleHunter(t *testing.T) {
	failureTracking := make(map[string]int)
	var mu sync.Mutex
	onFailure := func(hunterID string, failed bool) {
		mu.Lock()
		defer mu.Unlock()
		if failed {
			failureTracking[hunterID]++
		} else {
			failureTracking[hunterID] = 0
		}
	}

	manager := NewManager("", nil, onFailure, nil)

	hunterID := "hunter-1"
	filterChan := manager.AddChannel(hunterID)

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "192.168.1.*",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	huntersUpdated, err := manager.Update(filter)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), huntersUpdated, "should update 1 hunter")

	// Verify hunter received the update
	select {
	case receivedUpdate := <-filterChan:
		assert.Equal(t, management.FilterUpdateType_UPDATE_ADD, receivedUpdate.UpdateType)
		assert.Equal(t, filter.Id, receivedUpdate.Filter.Id)
		assert.Equal(t, filter.Pattern, receivedUpdate.Filter.Pattern)
	case <-time.After(time.Second):
		t.Fatal("filter update not received")
	}
}

func TestManager_Update_MultipleHunters(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	// Setup 3 hunters
	channels := make(map[string]chan *management.FilterUpdate)
	for i := 1; i <= 3; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		channels[hunterID] = manager.AddChannel(hunterID)
	}

	filter := &management.Filter{
		Id:      "filter-global",
		Pattern: "tcp",
		Type:    management.FilterType_FILTER_BPF,
		Enabled: true,
	}

	huntersUpdated, err := manager.Update(filter)
	assert.NoError(t, err)
	assert.Equal(t, uint32(3), huntersUpdated, "should update all 3 hunters")

	// Verify all hunters received the update
	for hunterID, filterChan := range channels {
		select {
		case receivedUpdate := <-filterChan:
			assert.Equal(t, management.FilterUpdateType_UPDATE_ADD, receivedUpdate.UpdateType)
			assert.Equal(t, filter.Id, receivedUpdate.Filter.Id)
		case <-time.After(time.Second):
			t.Fatalf("hunter %s did not receive filter update", hunterID)
		}
	}
}

func TestManager_Update_UpdateTypes(t *testing.T) {
	testCases := []struct {
		name       string
		operation  func(*Manager, *management.Filter) (uint32, error)
		updateType management.FilterUpdateType
	}{
		{"ADD", func(m *Manager, f *management.Filter) (uint32, error) { return m.Update(f) }, management.FilterUpdateType_UPDATE_ADD},
		{"MODIFY", func(m *Manager, f *management.Filter) (uint32, error) {
			// First add the filter
			m.Update(f)
			// Drain the channel
			hunterChan := m.channels["hunter-test"]
			<-hunterChan
			// Then modify it
			return m.Update(f)
		}, management.FilterUpdateType_UPDATE_MODIFY},
		{"DELETE", func(m *Manager, f *management.Filter) (uint32, error) {
			// First add the filter
			m.Update(f)
			// Drain the channel
			hunterChan := m.channels["hunter-test"]
			<-hunterChan
			// Then delete it
			return m.Delete(f.Id)
		}, management.FilterUpdateType_UPDATE_DELETE},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewManager("", nil, nil, nil)

			hunterID := "hunter-test"
			filterChan := manager.AddChannel(hunterID)

			filter := &management.Filter{
				Id:      "filter-test",
				Pattern: "test",
				Type:    management.FilterType_FILTER_IP_ADDRESS,
				Enabled: true,
			}

			huntersUpdated, err := tc.operation(manager, filter)
			assert.NoError(t, err)
			assert.Equal(t, uint32(1), huntersUpdated)

			select {
			case receivedUpdate := <-filterChan:
				assert.Equal(t, tc.updateType, receivedUpdate.UpdateType,
					"update type should match")
			case <-time.After(time.Second):
				t.Fatal("filter update not received")
			}
		})
	}
}

func TestManager_Update_ChannelFull(t *testing.T) {
	var failureCount uint32
	onFailure := func(hunterID string, failed bool) {
		if failed {
			atomic.AddUint32(&failureCount, 1)
		}
	}

	manager := NewManager("", nil, onFailure, nil)

	hunterID := "hunter-slow"
	// Create channel with capacity 1
	manager.channelsMu.Lock()
	manager.channels[hunterID] = make(chan *management.FilterUpdate, 1)
	manager.channelsMu.Unlock()

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "test",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	// Fill the channel
	manager.channels[hunterID] <- &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	// Try to send another - should timeout
	filter2 := &management.Filter{
		Id:      "filter-2",
		Pattern: "test2",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	huntersUpdated, err := manager.Update(filter2)
	assert.NoError(t, err, "Update itself should not error")

	// Should fail to send (channel full)
	assert.Equal(t, uint32(0), huntersUpdated, "should fail to update hunter (channel full)")

	// Verify failure was tracked
	assert.Greater(t, atomic.LoadUint32(&failureCount), uint32(0),
		"should track filter update failure")
}

func TestManager_Update_ConcurrentSends(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	numHunters := 10
	channels := make(map[string]chan *management.FilterUpdate)
	for i := 0; i < numHunters; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		channels[hunterID] = manager.AddChannel(hunterID)
	}

	filter := &management.Filter{
		Id:      "filter-concurrent",
		Pattern: "concurrent",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	// Send multiple updates concurrently
	var wg sync.WaitGroup
	numUpdates := 50
	for i := 0; i < numUpdates; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager.Update(filter)
		}()
	}

	wg.Wait()

	// Verify all hunters received at least one update
	for hunterID, filterChan := range channels {
		assert.Greater(t, len(filterChan), 0,
			"hunter %s should have received updates", hunterID)
	}
}

func TestManager_Update_NoHuntersConnected(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "test",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	huntersUpdated, err := manager.Update(filter)
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), huntersUpdated,
		"should update 0 hunters when none connected")
}

func TestManager_Update_TargetedFilter(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	// Setup 3 hunters
	channels := make(map[string]chan *management.FilterUpdate)
	for i := 1; i <= 3; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		channels[hunterID] = manager.AddChannel(hunterID)
	}

	// Filter targeted at specific hunters
	filter := &management.Filter{
		Id:            "filter-targeted",
		Pattern:       "192.168.*",
		Type:          management.FilterType_FILTER_IP_ADDRESS,
		Enabled:       true,
		TargetHunters: []string{"hunter-1", "hunter-2"},
	}

	huntersUpdated, err := manager.Update(filter)
	assert.NoError(t, err)

	// Should only update targeted hunters
	assert.Equal(t, uint32(2), huntersUpdated,
		"should only update targeted hunters")

	// Verify only targeted hunters received update
	receivedCount := 0
	for hunterID, filterChan := range channels {
		select {
		case <-filterChan:
			receivedCount++
			assert.Contains(t, filter.TargetHunters, hunterID,
				"only targeted hunters should receive update")
		case <-time.After(100 * time.Millisecond):
			// Hunter didn't receive - should be hunter-3
			assert.Equal(t, "hunter-3", hunterID,
				"non-targeted hunter should not receive update")
		}
	}

	assert.Equal(t, 2, receivedCount, "exactly 2 hunters should receive update")
}

func TestManager_Delete_NotFound(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	// Try to delete non-existent filter
	_, err := manager.Delete("non-existent-filter")
	assert.Error(t, err, "should return error when filter not found")
}

func TestManager_GetForHunter(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	// Add global filter (no target hunters)
	globalFilter := &management.Filter{
		Id:      "global-filter",
		Pattern: "global",
		Type:    management.FilterType_FILTER_BPF,
		Enabled: true,
	}
	manager.Update(globalFilter)

	// Add targeted filter
	targetedFilter := &management.Filter{
		Id:            "targeted-filter",
		Pattern:       "targeted",
		Type:          management.FilterType_FILTER_BPF,
		Enabled:       true,
		TargetHunters: []string{"hunter-1"},
	}
	manager.Update(targetedFilter)

	// Hunter-1 should get both filters
	hunter1Filters := manager.GetForHunter("hunter-1")
	assert.Len(t, hunter1Filters, 2, "hunter-1 should get both filters")

	// Hunter-2 should only get global filter
	hunter2Filters := manager.GetForHunter("hunter-2")
	assert.Len(t, hunter2Filters, 1, "hunter-2 should only get global filter")
	assert.Equal(t, "global-filter", hunter2Filters[0].Id)
}

func TestManager_Count(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	assert.Equal(t, 0, manager.Count(), "should start with 0 filters")

	filter1 := &management.Filter{
		Id:      "filter-1",
		Pattern: "test1",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}
	manager.Update(filter1)
	assert.Equal(t, 1, manager.Count(), "should have 1 filter")

	filter2 := &management.Filter{
		Id:      "filter-2",
		Pattern: "test2",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}
	manager.Update(filter2)
	assert.Equal(t, 2, manager.Count(), "should have 2 filters")

	manager.Delete("filter-1")
	assert.Equal(t, 1, manager.Count(), "should have 1 filter after deletion")
}

func TestManager_Update_ScopeChange_AllToSpecific(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	// Setup 3 hunters
	channels := make(map[string]chan *management.FilterUpdate)
	for i := 1; i <= 3; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		channels[hunterID] = manager.AddChannel(hunterID)
	}

	// Step 1: Add filter targeting ALL hunters (empty TargetHunters)
	globalFilter := &management.Filter{
		Id:            "filter-scope",
		Pattern:       "192.168.*",
		Type:          management.FilterType_FILTER_IP_ADDRESS,
		Enabled:       true,
		TargetHunters: []string{}, // All hunters
	}

	huntersUpdated, err := manager.Update(globalFilter)
	assert.NoError(t, err)
	assert.Equal(t, uint32(3), huntersUpdated, "should update all 3 hunters")

	// Verify all hunters received the ADD update
	for hunterID, filterChan := range channels {
		select {
		case receivedUpdate := <-filterChan:
			assert.Equal(t, management.FilterUpdateType_UPDATE_ADD, receivedUpdate.UpdateType,
				"hunter %s should receive ADD", hunterID)
			assert.Equal(t, "filter-scope", receivedUpdate.Filter.Id)
		case <-time.After(time.Second):
			t.Fatalf("hunter %s did not receive initial ADD", hunterID)
		}
	}

	// Step 2: Update filter to target ONLY hunter-1 (scope change)
	specificFilter := &management.Filter{
		Id:            "filter-scope",
		Pattern:       "192.168.*",
		Type:          management.FilterType_FILTER_IP_ADDRESS,
		Enabled:       true,
		TargetHunters: []string{"hunter-1"}, // Only hunter-1
	}

	huntersUpdated, err = manager.Update(specificFilter)
	assert.NoError(t, err)
	// Should send MODIFY to hunter-1 and DELETE to hunter-2, hunter-3
	// Only MODIFY counts as "updated", DELETE is a separate operation
	assert.Equal(t, uint32(1), huntersUpdated, "should update 1 hunter (hunter-1)")

	// Step 3: Verify update delivery
	// hunter-1 should receive MODIFY
	select {
	case receivedUpdate := <-channels["hunter-1"]:
		assert.Equal(t, management.FilterUpdateType_UPDATE_MODIFY, receivedUpdate.UpdateType,
			"hunter-1 should receive MODIFY")
		assert.Equal(t, "filter-scope", receivedUpdate.Filter.Id)
	case <-time.After(time.Second):
		t.Fatal("hunter-1 did not receive MODIFY")
	}

	// hunter-2 and hunter-3 should receive DELETE
	for _, hunterID := range []string{"hunter-2", "hunter-3"} {
		select {
		case receivedUpdate := <-channels[hunterID]:
			assert.Equal(t, management.FilterUpdateType_UPDATE_DELETE, receivedUpdate.UpdateType,
				"%s should receive DELETE to remove filter", hunterID)
			assert.Equal(t, "filter-scope", receivedUpdate.Filter.Id)
		case <-time.After(time.Second):
			t.Fatalf("%s did not receive DELETE", hunterID)
		}
	}

	// Step 4: Verify GetForHunter reflects new scope
	hunter1Filters := manager.GetForHunter("hunter-1")
	assert.Len(t, hunter1Filters, 1, "hunter-1 should have 1 filter")

	hunter2Filters := manager.GetForHunter("hunter-2")
	assert.Len(t, hunter2Filters, 0, "hunter-2 should have 0 filters")

	hunter3Filters := manager.GetForHunter("hunter-3")
	assert.Len(t, hunter3Filters, 0, "hunter-3 should have 0 filters")
}

func TestManager_Update_ScopeChange_SpecificToAll(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	// Setup 3 hunters
	channels := make(map[string]chan *management.FilterUpdate)
	for i := 1; i <= 3; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		channels[hunterID] = manager.AddChannel(hunterID)
	}

	// Step 1: Add filter targeting ONLY hunter-1
	specificFilter := &management.Filter{
		Id:            "filter-scope",
		Pattern:       "tcp",
		Type:          management.FilterType_FILTER_BPF,
		Enabled:       true,
		TargetHunters: []string{"hunter-1"},
	}

	huntersUpdated, err := manager.Update(specificFilter)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), huntersUpdated, "should update 1 hunter")

	// Drain the channel
	<-channels["hunter-1"]

	// Step 2: Update filter to target ALL hunters (expand scope)
	globalFilter := &management.Filter{
		Id:            "filter-scope",
		Pattern:       "tcp",
		Type:          management.FilterType_FILTER_BPF,
		Enabled:       true,
		TargetHunters: []string{}, // All hunters
	}

	huntersUpdated, err = manager.Update(globalFilter)
	assert.NoError(t, err)
	assert.Equal(t, uint32(3), huntersUpdated, "should update all 3 hunters")

	// Step 3: Verify all hunters received MODIFY (no DELETE sent when expanding)
	for hunterID, filterChan := range channels {
		select {
		case receivedUpdate := <-filterChan:
			assert.Equal(t, management.FilterUpdateType_UPDATE_MODIFY, receivedUpdate.UpdateType,
				"%s should receive MODIFY", hunterID)
			assert.Equal(t, "filter-scope", receivedUpdate.Filter.Id)
		case <-time.After(time.Second):
			t.Fatalf("%s did not receive MODIFY", hunterID)
		}
	}

	// Step 4: Verify GetForHunter reflects new scope
	for i := 1; i <= 3; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		filters := manager.GetForHunter(hunterID)
		assert.Len(t, filters, 1, "%s should have 1 filter", hunterID)
	}
}

func TestManager_Update_ScopeChange_SpecificToSpecific(t *testing.T) {
	manager := NewManager("", nil, nil, nil)

	// Setup 4 hunters
	channels := make(map[string]chan *management.FilterUpdate)
	for i := 1; i <= 4; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		channels[hunterID] = manager.AddChannel(hunterID)
	}

	// Step 1: Add filter targeting hunter-1 and hunter-2
	filter := &management.Filter{
		Id:            "filter-scope",
		Pattern:       "udp",
		Type:          management.FilterType_FILTER_BPF,
		Enabled:       true,
		TargetHunters: []string{"hunter-1", "hunter-2"},
	}

	huntersUpdated, err := manager.Update(filter)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), huntersUpdated, "should update 2 hunters")

	// Drain channels
	<-channels["hunter-1"]
	<-channels["hunter-2"]

	// Step 2: Update filter to target hunter-2 and hunter-3
	// This should:
	// - Send DELETE to hunter-1 (removed)
	// - Send MODIFY to hunter-2 (still targeted)
	// - Send MODIFY to hunter-3 (added)
	// - Send nothing to hunter-4 (not targeted)
	updatedFilter := &management.Filter{
		Id:            "filter-scope",
		Pattern:       "udp",
		Type:          management.FilterType_FILTER_BPF,
		Enabled:       true,
		TargetHunters: []string{"hunter-2", "hunter-3"},
	}

	huntersUpdated, err = manager.Update(updatedFilter)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), huntersUpdated, "should update 2 hunters (hunter-2, hunter-3)")

	// Step 3: Verify updates
	// hunter-1 should receive DELETE
	select {
	case receivedUpdate := <-channels["hunter-1"]:
		assert.Equal(t, management.FilterUpdateType_UPDATE_DELETE, receivedUpdate.UpdateType,
			"hunter-1 should receive DELETE")
		assert.Equal(t, "filter-scope", receivedUpdate.Filter.Id)
	case <-time.After(time.Second):
		t.Fatal("hunter-1 did not receive DELETE")
	}

	// hunter-2 should receive MODIFY
	select {
	case receivedUpdate := <-channels["hunter-2"]:
		assert.Equal(t, management.FilterUpdateType_UPDATE_MODIFY, receivedUpdate.UpdateType,
			"hunter-2 should receive MODIFY")
		assert.Equal(t, "filter-scope", receivedUpdate.Filter.Id)
	case <-time.After(time.Second):
		t.Fatal("hunter-2 did not receive MODIFY")
	}

	// hunter-3 should receive MODIFY
	select {
	case receivedUpdate := <-channels["hunter-3"]:
		assert.Equal(t, management.FilterUpdateType_UPDATE_MODIFY, receivedUpdate.UpdateType,
			"hunter-3 should receive MODIFY")
		assert.Equal(t, "filter-scope", receivedUpdate.Filter.Id)
	case <-time.After(time.Second):
		t.Fatal("hunter-3 did not receive MODIFY")
	}

	// hunter-4 should receive nothing
	select {
	case <-channels["hunter-4"]:
		t.Fatal("hunter-4 should not receive any update")
	case <-time.After(100 * time.Millisecond):
		// Expected - no update
	}

	// Step 4: Verify GetForHunter reflects new scope
	hunter1Filters := manager.GetForHunter("hunter-1")
	assert.Len(t, hunter1Filters, 0, "hunter-1 should have 0 filters")

	hunter2Filters := manager.GetForHunter("hunter-2")
	assert.Len(t, hunter2Filters, 1, "hunter-2 should have 1 filter")

	hunter3Filters := manager.GetForHunter("hunter-3")
	assert.Len(t, hunter3Filters, 1, "hunter-3 should have 1 filter")

	hunter4Filters := manager.GetForHunter("hunter-4")
	assert.Len(t, hunter4Filters, 0, "hunter-4 should have 0 filters")
}
