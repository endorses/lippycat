package processor

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestPushFilterUpdate_SingleHunter(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	hunterID := "hunter-1"
	filterChan := make(chan *management.FilterUpdate, 10)
	p.filterChannels[hunterID] = filterChan
	p.hunters[hunterID] = &ConnectedHunter{
		ID:     hunterID,
		Status: management.HunterStatus_STATUS_HEALTHY,
	}

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "192.168.1.*",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)

	assert.Equal(t, uint32(1), huntersUpdated, "should update 1 hunter")

	select {
	case receivedUpdate := <-filterChan:
		assert.Equal(t, management.FilterUpdateType_UPDATE_ADD, receivedUpdate.UpdateType)
		assert.Equal(t, filter.Id, receivedUpdate.Filter.Id)
		assert.Equal(t, filter.Pattern, receivedUpdate.Filter.Pattern)
	case <-time.After(time.Second):
		t.Fatal("filter update not received")
	}
}

func TestPushFilterUpdate_MultipleHunters(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	// Setup 3 hunters
	for i := 1; i <= 3; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		filterChan := make(chan *management.FilterUpdate, 10)
		p.filterChannels[hunterID] = filterChan
		p.hunters[hunterID] = &ConnectedHunter{
			ID:     hunterID,
			Status: management.HunterStatus_STATUS_HEALTHY,
		}
	}

	filter := &management.Filter{
		Id:      "filter-global",
		Pattern: "tcp",
		Type:    management.FilterType_FILTER_BPF,
		Enabled: true,
	}

	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)

	assert.Equal(t, uint32(3), huntersUpdated, "should update all 3 hunters")

	// Verify all hunters received the update
	for hunterID, filterChan := range p.filterChannels {
		select {
		case receivedUpdate := <-filterChan:
			assert.Equal(t, management.FilterUpdateType_UPDATE_ADD, receivedUpdate.UpdateType)
			assert.Equal(t, filter.Id, receivedUpdate.Filter.Id)
		case <-time.After(time.Second):
			t.Fatalf("hunter %s did not receive filter update", hunterID)
		}
	}
}

func TestPushFilterUpdate_UpdateTypes(t *testing.T) {
	testCases := []struct {
		name       string
		updateType management.FilterUpdateType
	}{
		{"ADD", management.FilterUpdateType_UPDATE_ADD},
		{"MODIFY", management.FilterUpdateType_UPDATE_MODIFY},
		{"DELETE", management.FilterUpdateType_UPDATE_DELETE},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Processor{
				config:         Config{},
				filters:        make(map[string]*management.Filter),
				filterChannels: make(map[string]chan *management.FilterUpdate),
				hunters:        make(map[string]*ConnectedHunter),
			}

			hunterID := "hunter-test"
			filterChan := make(chan *management.FilterUpdate, 10)
			p.filterChannels[hunterID] = filterChan
			p.hunters[hunterID] = &ConnectedHunter{
				ID:     hunterID,
				Status: management.HunterStatus_STATUS_HEALTHY,
			}

			filter := &management.Filter{
				Id:      "filter-test",
				Pattern: "test",
				Type:    management.FilterType_FILTER_IP_ADDRESS,
				Enabled: true,
			}

			update := &management.FilterUpdate{
				UpdateType: tc.updateType,
				Filter:     filter,
			}

			huntersUpdated := p.pushFilterUpdate(filter, update)
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

func TestPushFilterUpdate_ChannelFull(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	hunterID := "hunter-slow"
	// Create channel with capacity 1
	filterChan := make(chan *management.FilterUpdate, 1)
	p.filterChannels[hunterID] = filterChan
	p.hunters[hunterID] = &ConnectedHunter{
		ID:     hunterID,
		Status: management.HunterStatus_STATUS_HEALTHY,
	}

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "test",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	// Fill the channel
	filterChan <- &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	// Try to send another - should timeout
	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_MODIFY,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)

	// Should fail to send (channel full)
	assert.Equal(t, uint32(0), huntersUpdated, "should fail to update hunter (channel full)")

	// Verify failure was tracked
	hunter := p.hunters[hunterID]
	assert.Greater(t, hunter.FilterUpdateFailures, uint32(0),
		"should track filter update failure")
}

func TestPushFilterUpdate_CircuitBreaker(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	hunterID := "hunter-failing"
	// Create channel with capacity 0 to force immediate timeout
	filterChan := make(chan *management.FilterUpdate)
	p.filterChannels[hunterID] = filterChan
	p.hunters[hunterID] = &ConnectedHunter{
		ID:     hunterID,
		Status: management.HunterStatus_STATUS_HEALTHY,
	}

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "test",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	// Send 10 updates to trigger circuit breaker
	for i := 0; i < 10; i++ {
		huntersUpdated := p.pushFilterUpdate(filter, update)
		assert.Equal(t, uint32(0), huntersUpdated, "should fail to send")
	}

	// After 10 failures, circuit breaker should trip
	hunter := p.hunters[hunterID]
	assert.Equal(t, uint32(10), hunter.FilterUpdateFailures,
		"should have 10 consecutive failures")
	assert.Equal(t, management.HunterStatus_STATUS_ERROR, hunter.Status,
		"hunter should be marked as ERROR after circuit breaker trips")
}

func TestPushFilterUpdate_ConcurrentSends(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	numHunters := 10
	for i := 0; i < numHunters; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		filterChan := make(chan *management.FilterUpdate, 100)
		p.filterChannels[hunterID] = filterChan
		p.hunters[hunterID] = &ConnectedHunter{
			ID:     hunterID,
			Status: management.HunterStatus_STATUS_HEALTHY,
		}
	}

	filter := &management.Filter{
		Id:      "filter-concurrent",
		Pattern: "concurrent",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	// Send multiple updates concurrently
	var wg sync.WaitGroup
	numUpdates := 50
	for i := 0; i < numUpdates; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.pushFilterUpdate(filter, update)
		}()
	}

	wg.Wait()

	// Verify all hunters received at least one update
	for hunterID, filterChan := range p.filterChannels {
		assert.Greater(t, len(filterChan), 0,
			"hunter %s should have received updates", hunterID)
	}
}

func TestPushFilterUpdate_SuccessResetsFailureCounter(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	hunterID := "hunter-recovery"
	filterChan := make(chan *management.FilterUpdate, 10)
	p.filterChannels[hunterID] = filterChan
	p.hunters[hunterID] = &ConnectedHunter{
		ID:                   hunterID,
		Status:               management.HunterStatus_STATUS_HEALTHY,
		FilterUpdateFailures: 5, // Pre-existing failures
	}

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "test",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)
	assert.Equal(t, uint32(1), huntersUpdated, "should successfully send")

	// Verify failure counter was reset
	hunter := p.hunters[hunterID]
	assert.Equal(t, uint32(0), hunter.FilterUpdateFailures,
		"successful send should reset failure counter")
}

func TestPushFilterUpdate_NoHuntersConnected(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "test",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)
	assert.Equal(t, uint32(0), huntersUpdated,
		"should update 0 hunters when none connected")
}

func TestPushFilterUpdate_TargetedFilter(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	// Setup 3 hunters
	for i := 1; i <= 3; i++ {
		hunterID := "hunter-" + string(rune('0'+i))
		filterChan := make(chan *management.FilterUpdate, 10)
		p.filterChannels[hunterID] = filterChan
		p.hunters[hunterID] = &ConnectedHunter{
			ID:     hunterID,
			Status: management.HunterStatus_STATUS_HEALTHY,
		}
	}

	// Filter targeted at specific hunters
	filter := &management.Filter{
		Id:            "filter-targeted",
		Pattern:       "192.168.*",
		Type:          management.FilterType_FILTER_IP_ADDRESS,
		Enabled:       true,
		TargetHunters: []string{"hunter-1", "hunter-2"},
	}

	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)

	// Should only update targeted hunters
	assert.Equal(t, uint32(2), huntersUpdated,
		"should only update targeted hunters")

	// Verify only targeted hunters received update
	receivedCount := 0
	for hunterID, filterChan := range p.filterChannels {
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

func TestPushFilterUpdate_PartialFailure(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	// Hunter 1: good channel
	filterChan1 := make(chan *management.FilterUpdate, 10)
	p.filterChannels["hunter-1"] = filterChan1
	p.hunters["hunter-1"] = &ConnectedHunter{
		ID:     "hunter-1",
		Status: management.HunterStatus_STATUS_HEALTHY,
	}

	// Hunter 2: full channel (will timeout)
	filterChan2 := make(chan *management.FilterUpdate)
	p.filterChannels["hunter-2"] = filterChan2
	p.hunters["hunter-2"] = &ConnectedHunter{
		ID:     "hunter-2",
		Status: management.HunterStatus_STATUS_HEALTHY,
	}

	// Hunter 3: good channel
	filterChan3 := make(chan *management.FilterUpdate, 10)
	p.filterChannels["hunter-3"] = filterChan3
	p.hunters["hunter-3"] = &ConnectedHunter{
		ID:     "hunter-3",
		Status: management.HunterStatus_STATUS_HEALTHY,
	}

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "test",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_ADD,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)

	// Should update 2 out of 3 hunters (hunter-2 fails)
	assert.Equal(t, uint32(2), huntersUpdated,
		"should update 2 hunters (1 failed)")

	// Verify hunter-2 has failure tracked
	assert.Greater(t, p.hunters["hunter-2"].FilterUpdateFailures, uint32(0),
		"failed hunter should have failure tracked")

	// Verify successful hunters have no failures
	assert.Equal(t, uint32(0), p.hunters["hunter-1"].FilterUpdateFailures)
	assert.Equal(t, uint32(0), p.hunters["hunter-3"].FilterUpdateFailures)
}

func TestPushFilterUpdate_RaceCondition(t *testing.T) {
	p := &Processor{
		config:         Config{},
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
		hunters:        make(map[string]*ConnectedHunter),
	}

	hunterID := "hunter-race"
	filterChan := make(chan *management.FilterUpdate, 100)
	p.filterChannels[hunterID] = filterChan
	p.hunters[hunterID] = &ConnectedHunter{
		ID:     hunterID,
		Status: management.HunterStatus_STATUS_HEALTHY,
	}

	filter := &management.Filter{
		Id:      "filter-1",
		Pattern: "test",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Enabled: true,
	}

	// Concurrent updates and reads
	var wg sync.WaitGroup
	var totalUpdated atomic.Uint32

	// Senders
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				update := &management.FilterUpdate{
					UpdateType: management.FilterUpdateType_UPDATE_ADD,
					Filter:     filter,
				}
				updated := p.pushFilterUpdate(filter, update)
				totalUpdated.Add(updated)
			}
		}()
	}

	// Receivers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-filterChan:
				// Consume updates
			case <-time.After(100 * time.Millisecond):
				return
			}
		}
	}()

	wg.Wait()

	// Verify no data races occurred (test will fail with -race if there are races)
	t.Logf("Total updates sent successfully: %d", totalUpdated.Load())
}
