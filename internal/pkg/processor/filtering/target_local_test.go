package filtering

import (
	"sync"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBPFUpdater records BPF filter updates for testing.
type mockBPFUpdater struct {
	mu      sync.Mutex
	filters []string
	err     error
}

func (m *mockBPFUpdater) SetBPFFilter(filter string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.filters = append(m.filters, filter)
	return nil
}

func (m *mockBPFUpdater) LastFilter() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.filters) == 0 {
		return ""
	}
	return m.filters[len(m.filters)-1]
}

func (m *mockBPFUpdater) FilterCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.filters)
}

// mockAppFilterUpdater records application filter updates for testing.
type mockAppFilterUpdater struct {
	mu      sync.Mutex
	filters []*management.Filter
	calls   int
}

func (m *mockAppFilterUpdater) UpdateFilters(filters []*management.Filter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.filters = filters
	m.calls++
}

func (m *mockAppFilterUpdater) GetFilters() []*management.Filter {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.filters
}

func (m *mockAppFilterUpdater) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestNewLocalTarget(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})

		assert.NotNil(t, target)
		assert.Empty(t, target.GetActiveFilters())
		assert.Equal(t, 0, target.FilterCount())
		assert.Equal(t, "", target.GetBaseBPF())
	})

	t.Run("with base BPF", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{
			BaseBPF: "port 5060",
		})

		assert.Equal(t, "port 5060", target.GetBaseBPF())
	})
}

func TestLocalTarget_ApplyFilter(t *testing.T) {
	t.Run("nil filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})

		count, err := target.ApplyFilter(nil)

		assert.NoError(t, err)
		assert.Equal(t, uint32(0), count)
		assert.Equal(t, 0, target.FilterCount())
	})

	t.Run("empty ID", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})

		count, err := target.ApplyFilter(&management.Filter{
			Id:      "",
			Pattern: "test",
		})

		assert.NoError(t, err)
		assert.Equal(t, uint32(0), count)
	})

	t.Run("BPF filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		count, err := target.ApplyFilter(&management.Filter{
			Id:      "test-1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})

		assert.NoError(t, err)
		assert.Equal(t, uint32(1), count)
		assert.Equal(t, 1, target.FilterCount())
		assert.Equal(t, "port 5060", bpfUpdater.LastFilter())
	})

	t.Run("IP address filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		count, err := target.ApplyFilter(&management.Filter{
			Id:      "ip-1",
			Type:    management.FilterType_FILTER_IP_ADDRESS,
			Pattern: "192.168.1.100",
			Enabled: true,
		})

		assert.NoError(t, err)
		assert.Equal(t, uint32(1), count)
		assert.Equal(t, "host 192.168.1.100", bpfUpdater.LastFilter())
	})

	t.Run("CIDR filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		count, err := target.ApplyFilter(&management.Filter{
			Id:      "net-1",
			Type:    management.FilterType_FILTER_IP_ADDRESS,
			Pattern: "10.0.0.0/8",
			Enabled: true,
		})

		assert.NoError(t, err)
		assert.Equal(t, uint32(1), count)
		assert.Equal(t, "net 10.0.0.0/8", bpfUpdater.LastFilter())
	})

	t.Run("SIP user filter with app filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		appFilter := &mockAppFilterUpdater{}
		target.SetApplicationFilter(appFilter)

		count, err := target.ApplyFilter(&management.Filter{
			Id:      "sip-1",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "alice",
			Enabled: true,
		})

		assert.NoError(t, err)
		assert.Equal(t, uint32(1), count)

		filters := appFilter.GetFilters()
		require.Len(t, filters, 1)
		assert.Equal(t, "alice", filters[0].Pattern)
	})

	t.Run("update existing filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		// Add filter
		_, err := target.ApplyFilter(&management.Filter{
			Id:      "test-1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})
		require.NoError(t, err)

		// Update filter
		count, err := target.ApplyFilter(&management.Filter{
			Id:      "test-1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5061",
			Enabled: true,
		})

		assert.NoError(t, err)
		assert.Equal(t, uint32(1), count)
		assert.Equal(t, 1, target.FilterCount())
		assert.Equal(t, "port 5061", bpfUpdater.LastFilter())
	})

	t.Run("disabled filter not applied", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		count, err := target.ApplyFilter(&management.Filter{
			Id:      "test-1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: false, // Disabled
		})

		assert.NoError(t, err)
		assert.Equal(t, uint32(1), count)
		// Filter is stored but not applied (empty BPF)
		assert.Equal(t, 1, target.FilterCount())
	})
}

func TestLocalTarget_RemoveFilter(t *testing.T) {
	t.Run("empty ID", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})

		count, err := target.RemoveFilter("")

		assert.NoError(t, err)
		assert.Equal(t, uint32(0), count)
	})

	t.Run("non-existent filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})

		count, err := target.RemoveFilter("non-existent")

		assert.NoError(t, err)
		assert.Equal(t, uint32(0), count)
	})

	t.Run("remove existing filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		// Add filter
		_, err := target.ApplyFilter(&management.Filter{
			Id:      "test-1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})
		require.NoError(t, err)

		// Remove filter
		count, err := target.RemoveFilter("test-1")

		assert.NoError(t, err)
		assert.Equal(t, uint32(1), count)
		assert.Equal(t, 0, target.FilterCount())
	})
}

func TestLocalTarget_GetActiveFilters(t *testing.T) {
	target := NewLocalTarget(LocalTargetConfig{})

	// Add multiple filters
	_, _ = target.ApplyFilter(&management.Filter{
		Id:      "f1",
		Type:    management.FilterType_FILTER_BPF,
		Pattern: "port 5060",
		Enabled: true,
	})
	_, _ = target.ApplyFilter(&management.Filter{
		Id:      "f2",
		Type:    management.FilterType_FILTER_IP_ADDRESS,
		Pattern: "192.168.1.1",
		Enabled: true,
	})

	filters := target.GetActiveFilters()

	assert.Len(t, filters, 2)

	// Check that filters are present (order may vary due to map)
	ids := make(map[string]bool)
	for _, f := range filters {
		ids[f.Id] = true
	}
	assert.True(t, ids["f1"])
	assert.True(t, ids["f2"])
}

func TestLocalTarget_SupportsFilterType(t *testing.T) {
	t.Run("without app filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})

		// BPF-convertible types are always supported
		assert.True(t, target.SupportsFilterType(management.FilterType_FILTER_BPF))
		assert.True(t, target.SupportsFilterType(management.FilterType_FILTER_IP_ADDRESS))

		// VoIP types require app filter
		assert.False(t, target.SupportsFilterType(management.FilterType_FILTER_SIP_USER))
		assert.False(t, target.SupportsFilterType(management.FilterType_FILTER_PHONE_NUMBER))
		assert.False(t, target.SupportsFilterType(management.FilterType_FILTER_CALL_ID))
		assert.False(t, target.SupportsFilterType(management.FilterType_FILTER_CODEC))
	})

	t.Run("with app filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		target.SetApplicationFilter(&mockAppFilterUpdater{})

		// All filter types supported
		assert.True(t, target.SupportsFilterType(management.FilterType_FILTER_BPF))
		assert.True(t, target.SupportsFilterType(management.FilterType_FILTER_IP_ADDRESS))
		assert.True(t, target.SupportsFilterType(management.FilterType_FILTER_SIP_USER))
		assert.True(t, target.SupportsFilterType(management.FilterType_FILTER_PHONE_NUMBER))
		assert.True(t, target.SupportsFilterType(management.FilterType_FILTER_CALL_ID))
		assert.True(t, target.SupportsFilterType(management.FilterType_FILTER_CODEC))
	})
}

func TestLocalTarget_BPFGeneration(t *testing.T) {
	t.Run("single BPF filter", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})

		assert.Equal(t, "port 5060", bpfUpdater.LastFilter())
	})

	t.Run("multiple BPF filters combined with OR", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})
		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f2",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5061",
			Enabled: true,
		})

		lastFilter := bpfUpdater.LastFilter()
		// Order may vary, but both should be present
		assert.Contains(t, lastFilter, "port 5060")
		assert.Contains(t, lastFilter, "port 5061")
		assert.Contains(t, lastFilter, " or ")
	})

	t.Run("base BPF combined with filter using AND", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{
			BaseBPF: "udp",
		})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})

		assert.Equal(t, "(udp) and (port 5060)", bpfUpdater.LastFilter())
	})

	t.Run("mixed BPF and IP address filters", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})
		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f2",
			Type:    management.FilterType_FILTER_IP_ADDRESS,
			Pattern: "192.168.1.100",
			Enabled: true,
		})

		lastFilter := bpfUpdater.LastFilter()
		assert.Contains(t, lastFilter, "port 5060")
		assert.Contains(t, lastFilter, "host 192.168.1.100")
		assert.Contains(t, lastFilter, " or ")
	})

	t.Run("invalid IP address ignored", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f1",
			Type:    management.FilterType_FILTER_IP_ADDRESS,
			Pattern: "not-an-ip",
			Enabled: true,
		})

		// No BPF filter should be set for invalid IP
		// (the filter is stored but generates empty BPF)
		assert.Equal(t, 1, target.FilterCount())
	})

	t.Run("invalid CIDR ignored", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		target.SetBPFUpdater(bpfUpdater)

		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f1",
			Type:    management.FilterType_FILTER_IP_ADDRESS,
			Pattern: "192.168.1.0/33", // Invalid CIDR
			Enabled: true,
		})

		assert.Equal(t, 1, target.FilterCount())
	})
}

func TestLocalTarget_SetBaseBPF(t *testing.T) {
	target := NewLocalTarget(LocalTargetConfig{
		BaseBPF: "udp",
	})
	bpfUpdater := &mockBPFUpdater{}
	target.SetBPFUpdater(bpfUpdater)

	// Add a filter first
	_, _ = target.ApplyFilter(&management.Filter{
		Id:      "f1",
		Type:    management.FilterType_FILTER_BPF,
		Pattern: "port 5060",
		Enabled: true,
	})

	initialFilter := bpfUpdater.LastFilter()
	assert.Contains(t, initialFilter, "udp")

	// Update base BPF
	err := target.SetBaseBPF("tcp")

	assert.NoError(t, err)
	assert.Equal(t, "tcp", target.GetBaseBPF())

	newFilter := bpfUpdater.LastFilter()
	assert.Contains(t, newFilter, "tcp")
	assert.NotContains(t, newFilter, "udp")
}

func TestLocalTarget_FilterRouting(t *testing.T) {
	t.Run("BPF filters go to BPF updater only", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		appFilter := &mockAppFilterUpdater{}
		target.SetBPFUpdater(bpfUpdater)
		target.SetApplicationFilter(appFilter)

		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})

		// BPF filter should be applied
		assert.Equal(t, "port 5060", bpfUpdater.LastFilter())

		// App filter should receive empty list (BPF filters not routed there)
		filters := appFilter.GetFilters()
		assert.Empty(t, filters)
	})

	t.Run("SIP user filters go to app filter only", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		appFilter := &mockAppFilterUpdater{}
		target.SetBPFUpdater(bpfUpdater)
		target.SetApplicationFilter(appFilter)

		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "f1",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "alice",
			Enabled: true,
		})

		// App filter should receive the SIP user filter
		filters := appFilter.GetFilters()
		require.Len(t, filters, 1)
		assert.Equal(t, "alice", filters[0].Pattern)
	})

	t.Run("mixed filters routed correctly", func(t *testing.T) {
		target := NewLocalTarget(LocalTargetConfig{})
		bpfUpdater := &mockBPFUpdater{}
		appFilter := &mockAppFilterUpdater{}
		target.SetBPFUpdater(bpfUpdater)
		target.SetApplicationFilter(appFilter)

		// Add BPF filter
		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "bpf-1",
			Type:    management.FilterType_FILTER_BPF,
			Pattern: "port 5060",
			Enabled: true,
		})

		// Add SIP user filter
		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "sip-1",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "alice",
			Enabled: true,
		})

		// Add IP filter
		_, _ = target.ApplyFilter(&management.Filter{
			Id:      "ip-1",
			Type:    management.FilterType_FILTER_IP_ADDRESS,
			Pattern: "192.168.1.1",
			Enabled: true,
		})

		// BPF updater should have combined BPF + IP
		lastBPF := bpfUpdater.LastFilter()
		assert.Contains(t, lastBPF, "port 5060")
		assert.Contains(t, lastBPF, "host 192.168.1.1")

		// App filter should have only SIP user
		filters := appFilter.GetFilters()
		require.Len(t, filters, 1)
		assert.Equal(t, "alice", filters[0].Pattern)
		assert.Equal(t, management.FilterType_FILTER_SIP_USER, filters[0].Type)
	})
}

func TestLocalTarget_Concurrency(t *testing.T) {
	target := NewLocalTarget(LocalTargetConfig{})
	bpfUpdater := &mockBPFUpdater{}
	appFilter := &mockAppFilterUpdater{}
	target.SetBPFUpdater(bpfUpdater)
	target.SetApplicationFilter(appFilter)

	var wg sync.WaitGroup
	const numGoroutines = 10
	const numOperations = 100

	// Concurrent filter additions
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				id := "f-" + string(rune('A'+gid)) + "-" + string(rune('0'+j%10))
				_, _ = target.ApplyFilter(&management.Filter{
					Id:      id,
					Type:    management.FilterType_FILTER_BPF,
					Pattern: "port 5060",
					Enabled: true,
				})
			}
		}(i)
	}

	// Concurrent filter reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_ = target.GetActiveFilters()
				_ = target.FilterCount()
				_ = target.GetBaseBPF()
			}
		}()
	}

	wg.Wait()

	// Should not panic or have race conditions
	assert.True(t, target.FilterCount() > 0)
}
