//go:build cli || all

package voip

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func lifetimeTestPacket() gopacket.Packet {
	data := make([]byte, 64)
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo.Timestamp = time.Now()
	p.Metadata().CaptureInfo.CaptureLength = len(data)
	p.Metadata().CaptureInfo.Length = len(data)
	return p
}

func TestRTPWriteRaceWithCompletionClose(t *testing.T) {
	callID := "rtp-completion-race"
	call := createCallWithRTPWriter(t, callID)
	tracker := TestCallTracker(t)
	tracker.shuttingDown.Store(0)
	tracker.mu.Lock()
	tracker.callMap[callID] = call
	tracker.lruIndex[callID] = tracker.lruList.PushFront(callID)
	tracker.mu.Unlock()
	monitor := NewSniffCompletionMonitor(tracker, nil)
	packet := lifetimeTestPacket()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 250 {
				err := call.writeRTP(packet)
				if err != nil && !errors.Is(err, ErrWriterNotInitialized) {
					t.Errorf("unexpected RTP write result: %v", err)
					return
				}
			}
		}()
	}
	monitor.closeCallPcap(callID)
	wg.Wait()
	require.ErrorIs(t, call.writeRTP(packet), ErrWriterNotInitialized)
	tracker.mu.RLock()
	_, exists := tracker.callMap[callID]
	tracker.mu.RUnlock()
	require.False(t, exists)
}

func TestSIPWriteRaceWithLRUEviction(t *testing.T) {
	originalWriteVoIP := viper.GetBool("writeVoip")
	viper.Set("writeVoip", false)
	t.Cleanup(func() { viper.Set("writeVoip", originalWriteVoIP) })

	tracker := NewCallTrackerWithCapacity(1)
	t.Cleanup(tracker.Shutdown)
	call := createCallWithSIPWriter(t, "sip-lru-race")
	tracker.mu.Lock()
	tracker.callMap[call.CallID] = call
	tracker.lruIndex[call.CallID] = tracker.lruList.PushFront(call.CallID)
	tracker.touchCall(call.CallID)
	tracker.mu.Unlock()

	packet := lifetimeTestPacket()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 250 {
				err := call.writeSIP(packet)
				if err != nil && !errors.Is(err, ErrWriterNotInitialized) {
					t.Errorf("unexpected SIP write result: %v", err)
					return
				}
			}
		}()
	}
	require.NotNil(t, tracker.getOrCreateCall("replacement", layers.LinkTypeEthernet))
	wg.Wait()
	require.ErrorIs(t, call.writeSIP(packet), ErrWriterNotInitialized)
}

func TestAsyncWriteRaceWithClose(t *testing.T) {
	tracker := TestCallTracker(t)
	tracker.shuttingDown.Store(0)
	callID := "async-close-race"
	call := createCallWithSIPWriter(t, callID)
	tracker.mu.Lock()
	tracker.callMap[callID] = call
	tracker.mu.Unlock()
	t.Cleanup(func() {
		tracker.mu.Lock()
		delete(tracker.callMap, callID)
		tracker.mu.Unlock()
		_ = call.Close()
	})

	pool := NewAsyncWriterPoolWithTracker(tracker, 1, 16)
	req := PacketWriteRequest{CallID: callID, Packet: lifetimeTestPacket(), PacketType: PacketTypeSIP}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 250 {
				err := pool.processWriteRequest(req)
				if err != nil && !errors.Is(err, ErrWriterNotInitialized) {
					t.Errorf("unexpected async write result: %v", err)
					return
				}
			}
		}()
	}
	require.NoError(t, call.Close())
	wg.Wait()
	require.ErrorIs(t, pool.processWriteRequest(req), ErrWriterNotInitialized)
}
