package eventanalysis

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestLiveInventoryAcceptsTransportDelayedPackets(t *testing.T) {
	r, d, s := inventoryRuntime(t)
	base := time.Unix(1800000000, 0)
	var clock atomic.Int64
	localBase := base.Add(24 * time.Hour)
	clock.Store(localBase.UnixNano())
	r.cfg.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	r.cfg.ExpiryInterval = time.Millisecond
	r.cfg.LiveExpiry = true
	r.expiryStop = make(chan struct{})
	r.expiryDone = make(chan struct{})
	go r.runLiveExpiry()
	t.Cleanup(func() { r.Close(); require.NoError(t, d.Close(context.Background())) })
	waitExpiry := func(at time.Time) {
		require.Eventually(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return !r.expiryWatermark.Before(at) }, time.Second, time.Millisecond)
	}
	// Remote packets were captured before the client's housekeeping tick. They
	// arrive in capture order and are well inside the connection idle timeout.
	source := Source{NodeID: "tap-local", CaptureSource: "tap-local", CaptureScope: events.CaptureScopeFiltered}
	require.NoError(t, r.ObservePacket(source, dnsInventoryPacket(t, base, false, 17, "example.test")))
	clock.Store(localBase.Add(2 * time.Second).UnixNano())
	waitExpiry(base.Add(2 * time.Second))
	require.NoError(t, r.ObservePacket(source, dnsInventoryPacket(t, base.Add(10*time.Millisecond), true, 17, "example.test")))
	require.NoError(t, d.Flush(context.Background()))
	require.Len(t, inventoryEvents(s), 3, "two hosts and the DNS service appear before connection expiry")
	s.mu.Lock()
	connCount := 0
	for _, ev := range s.events {
		if ev.Kind() == events.KindConn {
			connCount++
		}
	}
	s.mu.Unlock()
	require.Zero(t, connCount, "inventory must arrive before the connection summary")
	// Advance the live clock rather than forcing EOF: the connected TUI must
	// receive the inventory while its packet subscription is still active.
	clock.Store(localBase.Add(6*time.Minute + 2*time.Second).UnixNano())
	waitExpiry(base.Add(6 * time.Minute))
	require.NoError(t, d.Flush(context.Background()))
	require.Len(t, inventoryEvents(s), 3, "connection expiry must not duplicate inventory")
}

func TestLiveExpiryDoesNotAdvanceCaptureAdmission(t *testing.T) {
	r, d, _ := inventoryRuntime(t)
	t.Cleanup(func() { r.Close(); require.NoError(t, d.Close(context.Background())) })
	base := time.Unix(1800000000, 0)
	local := base.Add(24 * time.Hour)
	r.cfg.Now = func() time.Time { return local }
	r.cfg.LiveExpiry = true
	r.expireIdle(local)
	require.True(t, r.watermark.IsZero(), "housekeeping before capture cannot reject initial packets")
	require.True(t, r.expiryWatermark.IsZero())
	require.NoError(t, r.ObservePacket(Source{NodeID: "tap-local"}, dnsInventoryPacket(t, base, false, 17, "example.test")))
	r.expireIdle(local.Add(time.Second))
	require.Equal(t, base, r.watermark)
	require.Equal(t, base.Add(time.Second), r.expiryWatermark)
	r.expireIdle(local.Add(-time.Second))
	require.Equal(t, base.Add(time.Second), r.expiryWatermark, "clock regression cannot undo expiry")
	r.EOF()
	r.expireIdle(local.Add(time.Hour))
	require.True(t, r.watermark.IsZero())
	require.True(t, r.expiryWatermark.IsZero())
}
