package auth

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"
)

// mockAddr implements net.Addr for testing
type mockAddr struct {
	addr string
}

func (m mockAddr) Network() string { return "tcp" }
func (m mockAddr) String() string  { return m.addr }

func contextWithIP(ip string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: mockAddr{addr: ip + ":55555"},
	})
}

func TestRateLimiter_BasicBlocking(t *testing.T) {
	rl := NewRateLimiterWithConfig(3, 100*time.Millisecond)
	defer rl.Stop()

	ctx := contextWithIP("192.168.1.1")

	// Should not be blocked initially
	assert.False(t, rl.IsBlocked(ctx))

	// Record failures up to threshold
	assert.False(t, rl.RecordFailure(ctx)) // 1st failure
	assert.False(t, rl.RecordFailure(ctx)) // 2nd failure
	assert.True(t, rl.RecordFailure(ctx))  // 3rd failure - now blocked

	// Should be blocked
	assert.True(t, rl.IsBlocked(ctx))

	// Wait for block to expire
	time.Sleep(150 * time.Millisecond)

	// Should no longer be blocked
	assert.False(t, rl.IsBlocked(ctx))
}

func TestRateLimiter_SuccessResetsFailures(t *testing.T) {
	rl := NewRateLimiterWithConfig(3, 100*time.Millisecond)
	defer rl.Stop()

	ctx := contextWithIP("192.168.1.2")

	// Record some failures
	rl.RecordFailure(ctx)
	rl.RecordFailure(ctx)

	// Successful auth should reset
	rl.RecordSuccess(ctx)

	// Should need 3 more failures to block
	assert.False(t, rl.RecordFailure(ctx))
	assert.False(t, rl.RecordFailure(ctx))
	assert.True(t, rl.RecordFailure(ctx)) // Now blocked
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiterWithConfig(2, 100*time.Millisecond)
	defer rl.Stop()

	ctx1 := contextWithIP("192.168.1.1")
	ctx2 := contextWithIP("192.168.1.2")

	// Block first IP
	rl.RecordFailure(ctx1)
	rl.RecordFailure(ctx1)

	// First IP should be blocked, second should not
	assert.True(t, rl.IsBlocked(ctx1))
	assert.False(t, rl.IsBlocked(ctx2))
}

func TestRateLimiter_FailureWindowExpiry(t *testing.T) {
	rl := NewRateLimiterWithConfig(3, 50*time.Millisecond)
	defer rl.Stop()

	ctx := contextWithIP("192.168.1.3")

	// Record failures but let window expire
	rl.RecordFailure(ctx)
	rl.RecordFailure(ctx)
	time.Sleep(60 * time.Millisecond)

	// Window expired, counter should reset
	assert.False(t, rl.RecordFailure(ctx)) // 1st in new window
	assert.False(t, rl.RecordFailure(ctx)) // 2nd in new window
	assert.True(t, rl.RecordFailure(ctx))  // 3rd - now blocked
}

func TestRateLimiter_NoIPContext(t *testing.T) {
	rl := NewRateLimiterWithConfig(2, 100*time.Millisecond)
	defer rl.Stop()

	// Context without peer info
	ctx := context.Background()

	// Should not block without IP
	assert.False(t, rl.IsBlocked(ctx))
	assert.False(t, rl.RecordFailure(ctx))
	assert.False(t, rl.RecordFailure(ctx))
	assert.False(t, rl.RecordFailure(ctx))
	assert.False(t, rl.IsBlocked(ctx))
}

func TestRateLimiter_IPv6(t *testing.T) {
	rl := NewRateLimiterWithConfig(2, 100*time.Millisecond)
	defer rl.Stop()

	// IPv6 context
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: mockAddr{addr: "[::1]:55555"},
	})

	rl.RecordFailure(ctx)
	assert.True(t, rl.RecordFailure(ctx))
	assert.True(t, rl.IsBlocked(ctx))
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"IPv4 with port", "192.168.1.1:55555", "192.168.1.1"},
		{"IPv6 with port", "[::1]:55555", "::1"},
		{"IPv6 full with port", "[2001:db8::1]:8080", "2001:db8::1"},
		{"IPv4 no port", "192.168.1.1", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := peer.NewContext(context.Background(), &peer.Peer{
				Addr: mockAddr{addr: tt.addr},
			})
			ip := extractClientIP(ctx)
			assert.Equal(t, tt.expected, ip)
		})
	}
}

func TestExtractClientIP_NoPeer(t *testing.T) {
	ip := extractClientIP(context.Background())
	assert.Empty(t, ip)
}

func TestRateLimiter_DefaultValues(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()

	require.NotNil(t, rl)
	assert.Equal(t, DefaultMaxFailures, rl.maxFailures)
	assert.Equal(t, DefaultBlockDuration, rl.blockDuration)
}

func TestRateLimiter_Cleanup(t *testing.T) {
	// Use very short durations for testing cleanup
	rl := &RateLimiter{
		failures:      make(map[string]*failureRecord),
		maxFailures:   2,
		blockDuration: 10 * time.Millisecond,
		done:          make(chan struct{}),
	}

	// Add some entries
	rl.failures["192.168.1.1"] = &failureRecord{
		count:     1,
		firstFail: time.Now().Add(-100 * time.Millisecond), // Old
	}
	rl.failures["192.168.1.2"] = &failureRecord{
		count:     1,
		firstFail: time.Now(), // Recent
	}

	// Run cleanup
	rl.cleanup()

	// Old entry should be removed, recent should remain
	_, exists1 := rl.failures["192.168.1.1"]
	_, exists2 := rl.failures["192.168.1.2"]
	assert.False(t, exists1, "old entry should be cleaned up")
	assert.True(t, exists2, "recent entry should remain")
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiterWithConfig(100, time.Second)
	defer rl.Stop()

	done := make(chan bool)

	// Spawn multiple goroutines accessing the rate limiter
	for i := 0; i < 10; i++ {
		go func(id int) {
			ctx := contextWithIP("192.168.1." + string(rune('0'+id)))
			for j := 0; j < 50; j++ {
				rl.IsBlocked(ctx)
				rl.RecordFailure(ctx)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestRateLimiter_BlockExpiryResetsOnNewFailure(t *testing.T) {
	rl := NewRateLimiterWithConfig(2, 50*time.Millisecond)
	defer rl.Stop()

	ctx := contextWithIP("192.168.1.10")

	// Get blocked
	rl.RecordFailure(ctx)
	rl.RecordFailure(ctx)
	assert.True(t, rl.IsBlocked(ctx))

	// Wait for block to expire
	time.Sleep(60 * time.Millisecond)
	assert.False(t, rl.IsBlocked(ctx))

	// New failure should start fresh
	assert.False(t, rl.RecordFailure(ctx)) // 1st failure in new window
	assert.True(t, rl.RecordFailure(ctx))  // 2nd failure - blocked again
}

func TestRateLimiter_RealTCPAddr(t *testing.T) {
	rl := NewRateLimiterWithConfig(2, 100*time.Millisecond)
	defer rl.Stop()

	// Use real net.TCPAddr
	addr := &net.TCPAddr{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 12345,
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})

	rl.RecordFailure(ctx)
	assert.True(t, rl.RecordFailure(ctx))
	assert.True(t, rl.IsBlocked(ctx))
}
