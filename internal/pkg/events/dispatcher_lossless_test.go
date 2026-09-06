package events

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLosslessDispatchPreservesIdentityOrderAndFinalEvents(t *testing.T) {
	producer, err := NewOfflineProducer("node", OfflineSession{InputIdentity: "fixture", AnalysisProfile: "test"})
	require.NoError(t, err)
	d := newTestDispatcher(t, 1, 1)
	d.cfg.Producer = producer
	all, dns := &testSink{}, &testSink{}
	require.NoError(t, d.Register(all))
	require.NoError(t, d.Register(dns, KindDNS))
	require.NoError(t, d.Start(context.Background()))
	for i := range 1000 {
		env := Envelope{UID: fmt.Sprint(i)}
		var ev Event = NewDNSEvent(env)
		if i%2 != 0 {
			ev = NewHTTPEvent(env)
		}
		require.True(t, d.EnqueueLossless(context.Background(), ev))
	}
	require.NoError(t, d.Close(context.Background()))
	require.Len(t, all.events, 1000)
	require.Len(t, dns.events, 500)
	for i, ev := range all.events {
		env := ev.Envelope()
		require.Equal(t, fmt.Sprint(i), env.UID)
		require.Equal(t, uint64(i+1), env.EventSequence)
		require.True(t, HasValidDeliveryIdentity(env))
		if i%2 == 0 {
			require.Equal(t, ev, dns.events[i/2])
		}
	}
	require.Equal(t, 1, all.flushes, "lossless admission must not flush each event")
	require.Zero(t, d.Stats().Dropped)
	require.Zero(t, d.Stats().SinkDropped)
}

func TestLosslessBlockedAdmissionCancellationAndStop(t *testing.T) {
	for _, cancelKind := range []string{"caller", "dispatcher", "stop"} {
		t.Run(cancelKind, func(t *testing.T) {
			release := make(chan struct{})
			entered := make(chan struct{})
			sink := &testSink{handle: func(Event) error {
				select {
				case <-entered:
				default:
					close(entered)
				}
				<-release
				return nil
			}}
			d := newTestDispatcher(t, 1, 1)
			defer func() {
				close(release)
				require.NoError(t, d.Stop(context.Background()))
				d.dispatchWG.Wait()
				d.sinkWG.Wait()
			}()
			require.NoError(t, d.Register(sink))
			runCtx, cancelRun := context.WithCancel(context.Background())
			defer cancelRun()
			require.NoError(t, d.Start(runCtx))
			require.True(t, d.EnqueueLossless(context.Background(), NewDNSEvent(Envelope{})))
			<-entered
			// Fill sink queue, dispatcher handoff, and dispatcher admission queue.
			for range 3 {
				require.True(t, d.EnqueueLossless(context.Background(), NewDNSEvent(Envelope{})))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			admitted := make(chan bool, 1)
			go func() { admitted <- d.EnqueueLossless(ctx, NewDNSEvent(Envelope{})) }()
			select {
			case <-admitted:
				t.Fatal("admission must wait while all queues are full")
			case <-time.After(10 * time.Millisecond):
			}
			// A second producer must observe its own cancellation while the
			// first producer remains blocked on queue capacity.
			secondCtx, cancelSecond := context.WithCancel(context.Background())
			second := make(chan bool, 1)
			go func() { second <- d.EnqueueLossless(secondCtx, NewDNSEvent(Envelope{})) }()
			cancelSecond()
			select {
			case ok := <-second:
				require.False(t, ok)
			case <-time.After(time.Second):
				t.Fatal("second producer blocked despite cancellation")
			}
			switch cancelKind {
			case "caller":
				cancel()
			case "dispatcher":
				cancelRun()
			case "stop":
				flushed := make(chan error, 1)
				go func() { flushed <- d.Flush(context.Background()) }()
				select {
				case <-flushed:
					t.Fatal("flush completed while all queues are full")
				case <-time.After(10 * time.Millisecond):
				}
				stopCtx, cancelStop := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancelStop()
				stopped := make(chan error, 1)
				go func() { stopped <- d.Stop(stopCtx) }()
				select {
				case err := <-stopped:
					require.ErrorIs(t, err, context.DeadlineExceeded)
				case <-time.After(time.Second):
					t.Fatal("Stop blocked behind lossless admission")
				}
				select {
				case err := <-flushed:
					require.Error(t, err)
				case <-time.After(time.Second):
					t.Fatal("flush did not release its lock during Stop")
				}
			}
			select {
			case ok := <-admitted:
				require.False(t, ok)
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt admission")
			}
		})
	}
}

func BenchmarkLosslessDispatcherAdmission(b *testing.B) {
	for _, flushEach := range []bool{true, false} {
		b.Run(fmt.Sprintf("flush_each=%t", flushEach), func(b *testing.B) {
			d, err := NewDispatcher(Config{QueueSize: 256, SinkQueueSize: 256})
			require.NoError(b, err)
			require.NoError(b, d.Register(&discardLosslessSink{}))
			require.NoError(b, d.Start(context.Background()))
			ev := NewDNSEvent(Envelope{})
			b.ResetTimer()
			for range b.N {
				if flushEach {
					if err := d.Flush(context.Background()); err != nil {
						b.Fatal(err)
					}
					if !d.Enqueue(ev) {
						b.Fatal("event dropped")
					}
				} else if !d.EnqueueLossless(context.Background(), ev) {
					b.Fatal("event dropped")
				}
			}
			require.NoError(b, d.Stop(context.Background()))
		})
	}
}

type discardLosslessSink struct{}

func (*discardLosslessSink) HandleEvent(context.Context, Event) error { return nil }
func (*discardLosslessSink) Flush(context.Context) error              { return nil }
func (*discardLosslessSink) Close(context.Context) error              { return nil }
