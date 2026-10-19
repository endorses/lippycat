//go:build li

package li

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

type responseProduct struct {
	name string
	d    CallCorrelationDecision
}

func newResponseContract(t *testing.T, config CallCorrelationConfig, store CallCorrelationPersistence) (*CallCorrelator, time.Time, chan time.Time) {
	t.Helper()
	config.ResponseWait = true
	config.ResponseWaitWindow = time.Hour
	c, now := newContractCorrelator(t, config, store)
	expired := make(chan time.Time, 1)
	c.waitAfter = func(time.Duration) <-chan time.Time { return expired }
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	return c, *now, expired
}

func responseFor(request *types.PacketDisplay) *types.PacketDisplay {
	response, _ := cloneCorrelationObservation(request)
	response.SrcIP, response.DstIP = request.DstIP, request.SrcIP
	response.VoIPData.Method, response.VoIPData.Status = "", 100
	response.VoIPData.ToTag = "response-tag"
	return response
}

func queueResponseProduct(t *testing.T, c *CallCorrelator, ctx context.Context, packet *types.PacketDisplay, name string, out chan responseProduct) {
	t.Helper()
	require.NoError(t, c.ResolveAsync(ctx, packet, []CallCorrelationTask{correlationTaskX}, 100, func(d CallCorrelationDecision) {
		c.Published(d)
		out <- responseProduct{name, d}
	}))
}

func takeResponseProduct(t *testing.T, out <-chan responseProduct) responseProduct {
	t.Helper()
	select {
	case result := <-out:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("response-wait worker did not reach explicit test handoff")
		return responseProduct{}
	}
}

func TestCallCorrelationResponseWaitRequestFIFOAndCandidate(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	c, now, _ := newResponseContract(t, cfg, nil)
	root := contractResolve(c, contractInvite("response-root", 0, now))
	invite := contractInvite("response-child", 1, now.Add(time.Millisecond))
	out := make(chan responseProduct, 4)
	queueResponseProduct(t, c, t.Context(), responseFor(invite), "response", out)
	stats := c.Stats()
	require.Equal(t, 1, stats.PendingDialogs)
	require.Equal(t, 1, stats.PendingPackets)
	require.Positive(t, stats.PendingBytes)
	require.Equal(t, 1, stats.Records, "response must not reserve its own ID")
	rtp := contractInvite(invite.VoIPData.CallID, 1, now)
	rtp.VoIPData.IsRTP = true
	queueResponseProduct(t, c, t.Context(), rtp, "media", out)
	queueResponseProduct(t, c, t.Context(), invite, "request", out)
	for _, name := range []string{"response", "media", "request"} {
		product := takeResponseProduct(t, out)
		require.Equal(t, name, product.name)
		require.Equal(t, root.CorrelationID, product.d.CorrelationID)
	}
	c.asyncWG.Wait()
	third := contractResolve(c, contractInvite("response-third", 2, now.Add(2*time.Millisecond)))
	require.Equal(t, root.CorrelationID, third.CorrelationID, "late initial request must create candidate evidence")
	stats = c.Stats()
	require.Zero(t, stats.PendingDialogs)
	require.Zero(t, stats.PendingPackets)
	require.Zero(t, stats.PendingBytes)
	require.EqualValues(t, 1, stats.ResponseWait["request"])
	stats.ResponseWait["request"] = 9
	require.EqualValues(t, 1, c.Stats().ResponseWait["request"], "status maps must be copies")
}

func TestCallCorrelationResponseWaitTimeoutAndTransactionEvidence(t *testing.T) {
	for _, kind := range []string{"timeout", "mismatched-branch", "reinvite", "finalized"} {
		t.Run(kind, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			c, now, expired := newResponseContract(t, cfg, nil)
			root := contractResolve(c, contractInvite("timeout-root", 0, now))
			invite := contractInvite("timeout-child", 1, now.Add(time.Millisecond))
			out := make(chan responseProduct, 3)
			queueResponseProduct(t, c, t.Context(), responseFor(invite), "response", out)
			if kind == "mismatched-branch" || kind == "reinvite" {
				wrong, _ := cloneCorrelationObservation(invite)
				if kind == "reinvite" {
					wrong.VoIPData.ToTag = "established-dialog"
				} else {
					wrong.VoIPData.ViaBranch = "z9hG4bK-different"
				}
				queueResponseProduct(t, c, t.Context(), wrong, "wrong-request", out)
				require.Equal(t, 0, len(out), "unrelated request cannot promote a response")
			}
			if kind == "finalized" {
				c.Finalize(invite.VoIPData.CallID)
			} else {
				expired <- time.Now()
			}
			product := takeResponseProduct(t, out)
			require.Equal(t, "response", product.name)
			require.NotEqual(t, root.CorrelationID, product.d.CorrelationID)
			if kind == "mismatched-branch" || kind == "reinvite" {
				require.Equal(t, product.d, takeResponseProduct(t, out).d)
			}
			c.asyncWG.Wait()
			require.Equal(t, product.d, c.Resolve(invite, []CallCorrelationTask{correlationTaskX}), "late evidence cannot change a reserved decision")
		})
	}
}

func TestCallCorrelationResponseWaitLogicalDeadlineIndependentOfStore(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.NumberChaining = true
	c, now, _ := newResponseContract(t, cfg, nil)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	c.waitNow = func() time.Time { return time.Unix(0, clock.Load()) }
	invite := contractInvite("logical-deadline", 0, now)
	out := make(chan responseProduct, 2)
	queueResponseProduct(t, c, t.Context(), responseFor(invite), "response", out)
	clock.Add(int64(2 * time.Hour))
	c.writeMu.Lock()
	require.NoError(t, c.Maintain(), "waiting release must not depend on store ownership")
	product := takeResponseProduct(t, out)
	c.writeMu.Unlock()
	require.Equal(t, hashCorrelationCallID(invite.VoIPData.CallID), product.d.CorrelationID)
	c.asyncWG.Wait()
	require.EqualValues(t, 1, c.Stats().ResponseWait["timeout"])
}

func TestCallCorrelationResponseWaitPressureBoundsAndFallback(t *testing.T) {
	for _, limit := range []string{"packets", "bytes", "dialogs"} {
		t.Run(limit, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.NumberChaining = true
			if limit == "packets" {
				cfg.MaxPendingPackets = 1
			} else if limit == "bytes" {
				cfg.MaxPendingBytes = 1100
			} else {
				cfg.MaxPendingDialogs = 1
			}
			c, now, expired := newResponseContract(t, cfg, nil)
			invite := contractInvite("bounded-child", 0, now)
			out := make(chan responseProduct, 3)
			queueResponseProduct(t, c, t.Context(), responseFor(invite), "response", out)
			if limit == "dialogs" {
				other := contractInvite("other-child", 4, now)
				queueResponseProduct(t, c, t.Context(), responseFor(other), "other-response", out)
				require.Equal(t, "other-response", takeResponseProduct(t, out).name)
				expired <- time.Now()
			} else {
				err := c.ResolveAsync(t.Context(), invite, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { t.Error("over-capacity snapshot was admitted") })
				require.ErrorIs(t, err, errCorrelationResponsePressure)
			}
			product := takeResponseProduct(t, out)
			require.Equal(t, hashCorrelationCallID(invite.VoIPData.CallID), product.d.CorrelationID)
			c.asyncWG.Wait()
			stats := c.Stats()
			require.Zero(t, stats.PendingBytes)
			require.Zero(t, stats.PendingPackets)
			require.EqualValues(t, 1, stats.ResponseWait["pressure"])
		})
	}
}

func TestCallCorrelationResponseWaitCancellationAndClose(t *testing.T) {
	for _, kind := range []string{"cancel", "close", "synchronous-cancel"} {
		t.Run(kind, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.NumberChaining = true
			c, now, _ := newResponseContract(t, cfg, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			response := responseFor(contractInvite("cancelled-child", 0, now))
			if kind == "synchronous-cancel" {
				cancel()
				_, err := c.ResolveContext(ctx, response, []CallCorrelationTask{correlationTaskX})
				require.ErrorIs(t, err, context.Canceled)
				return
			}
			require.NoError(t, c.ResolveAsync(ctx, response, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { t.Error("cancelled response was delivered") }))
			if kind == "cancel" {
				cancel()
				c.asyncWG.Wait()
			} else {
				require.NoError(t, c.Close())
			}
			stats := c.Stats()
			require.Zero(t, stats.Records)
			require.Zero(t, stats.PendingDialogs)
			require.Zero(t, stats.PendingPackets)
			require.Zero(t, stats.PendingBytes)
			require.EqualValues(t, 1, stats.ResponseWait[map[string]string{"cancel": "cancelled_packets", "close": "shutdown_packets"}[kind]])
		})
	}
}

func TestCallCorrelationResponseWaitPersistenceOutcomes(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.Committed, securestore.NotCommitted, securestore.Uncertain} {
		t.Run(securestore.OutcomeName(outcome), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			store := &correlationFakeStore{outcomes: []securestore.Outcome{outcome}}
			c, now, _ := newResponseContract(t, cfg, store)
			root := contractResolve(c, contractInvite("outcome-root", 0, now))
			invite := contractInvite("outcome-child", 1, now.Add(time.Millisecond))
			out := make(chan responseProduct, 2)
			queueResponseProduct(t, c, t.Context(), responseFor(invite), "response", out)
			queueResponseProduct(t, c, t.Context(), invite, "request", out)
			first, second := takeResponseProduct(t, out), takeResponseProduct(t, out)
			require.Equal(t, first.d, second.d)
			if outcome == securestore.NotCommitted {
				require.Equal(t, hashCorrelationCallID(invite.VoIPData.CallID), first.d.CorrelationID)
			} else {
				require.Equal(t, root.CorrelationID, first.d.CorrelationID)
			}
			c.asyncWG.Wait()
			require.Equal(t, first.d, c.Resolve(invite, []CallCorrelationTask{correlationTaskX}))
		})
	}
}

func TestCallCorrelationResponseWaitConcurrentRequestDeadlineAndFIFO(t *testing.T) {
	for run := range 20 {
		t.Run(fmt.Sprint(run), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			c, now, expired := newResponseContract(t, cfg, nil)
			contractResolve(c, contractInvite("race-root", 0, now))
			invite := contractInvite("race-child", 1, now.Add(time.Millisecond))
			out := make(chan responseProduct, 3)
			queueResponseProduct(t, c, t.Context(), responseFor(invite), "response", out)
			var requests sync.WaitGroup
			requests.Add(1)
			go func() {
				defer requests.Done()
				queueResponseProduct(t, c, t.Context(), invite, "request", out)
			}()
			expired <- time.Now()
			first, second := takeResponseProduct(t, out), takeResponseProduct(t, out)
			requests.Wait()
			require.Equal(t, "response", first.name)
			require.Equal(t, "request", second.name)
			require.Equal(t, first.d, second.d)
			c.asyncWG.Wait()
			require.Zero(t, c.Stats().PendingBytes)
		})
	}
}

func TestCallCorrelationResponseWaitCancelledResponsePreservesLiveArrival(t *testing.T) {
	for _, media := range []bool{false, true} {
		t.Run(fmt.Sprintf("media=%t", media), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			c, now, _ := newResponseContract(t, cfg, nil)
			entered, release := make(chan struct{}), make(chan struct{})
			c.waitAfter = func(time.Duration) <-chan time.Time {
				close(entered)
				<-release
				return make(chan time.Time)
			}
			root := contractResolve(c, contractInvite("cancel-live-root", 0, now))
			invite := contractInvite("cancel-live-child", 1, now.Add(time.Millisecond))
			ctx, cancel := context.WithCancel(context.Background())
			out := make(chan responseProduct, 2)
			queueResponseProduct(t, c, ctx, responseFor(invite), "cancelled-response", out)
			<-entered
			c.mu.Lock()
			entry := c.responsePending[invite.VoIPData.CallID]
			packet := entry.packets[0]
			c.mu.Unlock()
			cancel()
			c.cancelResponsePacket(entry, packet) // synchronize the cancellation race
			invite.VoIPData.IsRTP = media
			queueResponseProduct(t, c, t.Context(), invite, "live-arrival", out)
			close(release)
			product := takeResponseProduct(t, out)
			require.Equal(t, "live-arrival", product.name)
			require.NotEqual(t, root.CorrelationID, product.d.CorrelationID)
			c.asyncWG.Wait()
			require.Zero(t, len(out))
			require.Zero(t, c.Stats().PendingBytes)
		})
	}
}

func TestCallCorrelationResponseWaitPinDoesNotExtendEvidence(t *testing.T) {
	for _, expiry := range []string{"terminal", "idle"} {
		t.Run(expiry, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.SessionHeaders = []string{"X-Session"}
			cfg.TerminalGrace = time.Second
			c, now, _ := newResponseContract(t, cfg, nil)
			var clock atomic.Int64
			clock.Store(now.UnixNano())
			c.now = func() time.Time { return time.Unix(0, clock.Load()) }
			invite := contractHeader(contractInvite("pinned-evidence", 0, now), "X-Session", "synthetic")
			entered, release := make(chan struct{}), make(chan struct{})
			require.NoError(t, c.ResolveAsync(t.Context(), responseFor(invite), []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { close(entered); <-release }))
			require.NoError(t, c.ResolveAsync(t.Context(), invite, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {}))
			<-entered
			if expiry == "terminal" {
				c.Finalize(invite.VoIPData.CallID)
				clock.Add(int64(2 * time.Second))
			} else {
				clock.Add(int64(2 * c.lifetime))
			}
			c.mu.Lock()
			// Keep the protocol-specific candidate TTL live to isolate record
			// lifetime/terminal expiry from the independent candidate deadline.
			for _, candidate := range c.candidates {
				candidate.expires = c.now().Add(time.Hour)
			}
			c.mu.Unlock()
			later := contractHeader(contractInvite("after-logical-expiry", 4, now), "X-Session", "synthetic")
			decision := c.Resolve(later, []CallCorrelationTask{correlationTaskX})
			require.Equal(t, hashCorrelationCallID(later.VoIPData.CallID), decision.CorrelationID)
			close(release)
			c.asyncWG.Wait()
		})
	}
}

func TestCallCorrelationResponseWaitCancellationDuringCallbackIsNotSuppression(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.NumberChaining = true
	c, now, expired := newResponseContract(t, cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response := responseFor(contractInvite("delivered-then-cancelled", 0, now))
	delivered := make(chan struct{})
	require.NoError(t, c.ResolveAsync(ctx, response, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {
		cancel()
		close(delivered)
	}))
	expired <- time.Now()
	<-delivered
	c.asyncWG.Wait()
	require.Zero(t, c.Stats().ResponseWait["cancelled_packets"])
}
