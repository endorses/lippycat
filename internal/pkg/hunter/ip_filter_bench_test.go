//go:build hunter || tap || all

package hunter

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
)

// BenchmarkIPFilter_ExactMatch benchmarks exact IP matching with different filter counts
// Expected: O(1) - hash map lookup should be constant time regardless of filter count
func BenchmarkIPFilter_ExactMatch(b *testing.B) {
	filterCounts := []int{1, 10, 100, 1000}

	for _, count := range filterCounts {
		b.Run(fmt.Sprintf("filters=%d", count), func(b *testing.B) {
			af, _ := NewApplicationFilter(nil)

			// Create N exact IP filters
			filters := make([]*management.Filter, count)
			for i := 0; i < count; i++ {
				// Generate IPs like 10.0.0.1, 10.0.1.1, 10.0.2.1, ... (varying 2nd and 3rd octets)
				ip := fmt.Sprintf("10.%d.%d.1", (i/256)%256, i%256)
				filters[i] = &management.Filter{
					Type:    management.FilterType_FILTER_IP_ADDRESS,
					Pattern: ip,
				}
			}
			af.UpdateFilters(filters)

			// Use the first IP for matching (always a hit)
			matchAddr := mustParseAddr("10.0.0.1")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				af.matchSingleIP(matchAddr)
			}
		})
	}
}

// BenchmarkIPFilter_ExactMatch_Miss benchmarks exact IP matching with cache misses
// Expected: O(1) - hash map lookup should be constant time even for misses
func BenchmarkIPFilter_ExactMatch_Miss(b *testing.B) {
	filterCounts := []int{1, 10, 100, 1000}

	for _, count := range filterCounts {
		b.Run(fmt.Sprintf("filters=%d", count), func(b *testing.B) {
			af, _ := NewApplicationFilter(nil)

			// Create N exact IP filters in 10.x.x.x range
			filters := make([]*management.Filter, count)
			for i := 0; i < count; i++ {
				ip := fmt.Sprintf("10.%d.%d.1", (i/256)%256, i%256)
				filters[i] = &management.Filter{
					Type:    management.FilterType_FILTER_IP_ADDRESS,
					Pattern: ip,
				}
			}
			af.UpdateFilters(filters)

			// Use an IP outside the filter range (always a miss)
			missAddr := mustParseAddr("8.8.8.8")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				af.matchSingleIP(missAddr)
			}
		})
	}
}

// BenchmarkIPFilter_CIDRMatch benchmarks CIDR matching with different filter counts
// Expected: O(prefix length) - radix tree lookup
func BenchmarkIPFilter_CIDRMatch(b *testing.B) {
	filterCounts := []int{1, 10, 100, 1000}

	for _, count := range filterCounts {
		b.Run(fmt.Sprintf("filters=%d", count), func(b *testing.B) {
			af, _ := NewApplicationFilter(nil)

			// Create N CIDR filters like 10.0.0.0/24, 10.0.1.0/24, ...
			filters := make([]*management.Filter, count)
			for i := 0; i < count; i++ {
				cidr := fmt.Sprintf("10.%d.%d.0/24", (i>>8)&0xFF, i&0xFF)
				filters[i] = &management.Filter{
					Type:    management.FilterType_FILTER_IP_ADDRESS,
					Pattern: cidr,
				}
			}
			af.UpdateFilters(filters)

			// Match an IP in the first CIDR (always a hit)
			matchAddr := mustParseAddr("10.0.0.5")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				af.matchSingleIP(matchAddr)
			}
		})
	}
}

// BenchmarkIPFilter_CIDRMatch_Miss benchmarks CIDR matching with cache misses
// Expected: O(prefix length) - radix tree lookup for misses
func BenchmarkIPFilter_CIDRMatch_Miss(b *testing.B) {
	filterCounts := []int{1, 10, 100, 1000}

	for _, count := range filterCounts {
		b.Run(fmt.Sprintf("filters=%d", count), func(b *testing.B) {
			af, _ := NewApplicationFilter(nil)

			// Create N CIDR filters in 10.x.x.0/24 range
			filters := make([]*management.Filter, count)
			for i := 0; i < count; i++ {
				cidr := fmt.Sprintf("10.%d.%d.0/24", (i>>8)&0xFF, i&0xFF)
				filters[i] = &management.Filter{
					Type:    management.FilterType_FILTER_IP_ADDRESS,
					Pattern: cidr,
				}
			}
			af.UpdateFilters(filters)

			// Use an IP outside any CIDR (always a miss)
			missAddr := mustParseAddr("8.8.8.8")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				af.matchSingleIP(missAddr)
			}
		})
	}
}

// BenchmarkIPFilter_IPv6_ExactMatch benchmarks IPv6 exact matching
func BenchmarkIPFilter_IPv6_ExactMatch(b *testing.B) {
	filterCounts := []int{1, 10, 100, 1000}

	for _, count := range filterCounts {
		b.Run(fmt.Sprintf("filters=%d", count), func(b *testing.B) {
			af, _ := NewApplicationFilter(nil)

			// Create N IPv6 filters
			filters := make([]*management.Filter, count)
			for i := 0; i < count; i++ {
				ip := fmt.Sprintf("2001:db8::%d", i+1)
				filters[i] = &management.Filter{
					Type:    management.FilterType_FILTER_IP_ADDRESS,
					Pattern: ip,
				}
			}
			af.UpdateFilters(filters)

			matchAddr := mustParseAddr("2001:db8::1")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				af.matchSingleIP(matchAddr)
			}
		})
	}
}

// BenchmarkIPFilter_Mixed benchmarks mixed exact + CIDR matching
func BenchmarkIPFilter_Mixed(b *testing.B) {
	b.Run("exact_hit", func(b *testing.B) {
		af, _ := NewApplicationFilter(nil)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.1.1"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "10.0.0.0/8"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "172.16.0.0/12"},
		}
		af.UpdateFilters(filters)

		// Exact match is checked first (O(1))
		matchAddr := mustParseAddr("192.168.1.1")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			af.matchSingleIP(matchAddr)
		}
	})

	b.Run("cidr_hit", func(b *testing.B) {
		af, _ := NewApplicationFilter(nil)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.1.1"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "10.0.0.0/8"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "172.16.0.0/12"},
		}
		af.UpdateFilters(filters)

		// IP not in exact map, but in CIDR (O(1) miss + O(prefix) CIDR lookup)
		matchAddr := mustParseAddr("10.5.5.5")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			af.matchSingleIP(matchAddr)
		}
	})
}

// mustParseAddr is already defined in application_filter_test.go, but we redefine here
// to make this file self-contained for benchmark purposes
func init() {
	// Verify mustParseAddr works
	_ = mustParseAddrBench("192.168.1.1")
}

func mustParseAddrBench(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
