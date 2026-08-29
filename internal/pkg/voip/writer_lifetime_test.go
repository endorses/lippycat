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

func lifetimeTestRTPPacket(t *testing.T, dstPort layers.UDPPort) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 1, 2, 3, 4, 5},
		DstMAC:       []byte{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}}
	udp := &layers.UDP{SrcPort: 40000, DstPort: dstPort}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(make([]byte, 12))))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestRTPWriteRaceWithCompletionClose(t *testing.T) {
	callID := "rtp-completion-race"
	call := createCallWithRTPOutput(t, callID)
	tracker := TestCallTracker(t)
	tracker.replaceOutputForTest(trackerOutput(t, call.tracker))
	call.tracker = tracker
	tracker.shuttingDown.Store(0)
	adoptCallForTest(tracker, call)
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
	found, err := tracker.removeCall(callID)
	require.True(t, found)
	require.NoError(t, err)
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
	call := createCallWithSIPOutput(t, "sip-lru-race")
	tracker.replaceOutputForTest(trackerOutput(t, call.tracker))
	call.tracker = tracker
	adoptCallForTest(tracker, call)
	tracker.touchCall(call.CallID)

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
	call := createCallWithSIPOutput(t, callID)
	tracker.replaceOutputForTest(trackerOutput(t, call.tracker))
	call.tracker = tracker
	tracker.mu.Lock()
	tracker.callMap[callID] = call
	tracker.mu.Unlock()
	t.Cleanup(func() {
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
				if err != nil && !errors.Is(err, ErrWriterNotInitialized) && !errors.Is(err, ErrCallNotFound) {
					t.Errorf("unexpected async write result: %v", err)
					return
				}
			}
		}()
	}
	require.NoError(t, call.Close())
	wg.Wait()
	require.ErrorIs(t, pool.processWriteRequest(req), ErrCallNotFound)
}

func TestCallTrackerRejectsAdmissionAfterShutdownStarts(t *testing.T) {
	tracker := TestCallTracker(t)
	existing := tracker.GetOrCreateCall("existing", layers.LinkTypeEthernet)
	require.NotNil(t, existing)

	tracker.Shutdown()
	require.Nil(t, tracker.GetOrCreateCall("new", layers.LinkTypeEthernet))
	require.Nil(t, tracker.GetOrCreateCall("existing", layers.LinkTypeEthernet))
}

func TestSyncWriteAdmissionIsSerializedWithShutdown(t *testing.T) {
	tracker := TestCallTracker(t)
	call := tracker.GetOrCreateCall("write-shutdown-gate", layers.LinkTypeEthernet)
	require.NotNil(t, call)

	tracker.writeGateMu.Lock()
	result := make(chan error, 1)
	go func() { result <- tracker.writeRTPSync(call.CallID, lifetimeTestPacket()) }()
	tracker.shuttingDown.Store(1)
	tracker.writeGateMu.Unlock()

	require.ErrorIs(t, <-result, ErrShuttingDown)
	tracker.Shutdown()
}

func TestRTPActivityPreventsExpirationWithoutOutput(t *testing.T) {
	config := DefaultConfig()
	config.WriteVoIP = false
	config.CallExpirationTime = time.Minute
	tracker := NewCallTrackerWithConfig(config)
	t.Cleanup(tracker.Shutdown)
	call := tracker.GetOrCreateCall("active-media", layers.LinkTypeEthernet)
	require.NotNil(t, call)
	tracker.registerEndpoint("192.0.2.2:20000", call.CallID)

	tracker.mu.Lock()
	call.LastUpdated = time.Now().Add(-2 * time.Minute)
	tracker.mu.Unlock()
	require.Equal(t, call.CallID, tracker.GetCallIDForPacket(lifetimeTestRTPPacket(t, 20000)))

	tracker.cleanupOldCalls()
	got, err := tracker.GetCall(call.CallID)
	require.NoError(t, err)
	require.Same(t, call, got)
}

func TestStaleCompletionDoesNotCloseReusedCallID(t *testing.T) {
	config := DefaultConfig()
	config.PCAPGracePeriod = 20 * time.Millisecond
	tracker := NewCallTrackerWithConfig(config)
	t.Cleanup(tracker.Shutdown)
	oldCall := tracker.GetOrCreateCall("reused-generation", layers.LinkTypeEthernet)
	require.NotNil(t, oldCall)
	oldCall.SetCallInfoState("BYE")

	found, err := tracker.removeCall(oldCall.CallID)
	require.True(t, found)
	require.NoError(t, err)
	newCall := tracker.GetOrCreateCall(oldCall.CallID, layers.LinkTypeEthernet)
	require.NotNil(t, newCall)
	require.NotSame(t, oldCall, newCall)

	time.Sleep(2 * config.PCAPGracePeriod)
	got, err := tracker.GetCall(oldCall.CallID)
	require.NoError(t, err)
	require.Same(t, newCall, got)
}

func TestCompletedCallClosesThroughRegistryLifecycle(t *testing.T) {
	config := DefaultConfig()
	config.PCAPGracePeriod = 20 * time.Millisecond
	output := &recordingCallOutput{}
	tracker := NewCallTrackerWithOutput(config, output)
	t.Cleanup(tracker.Shutdown)

	call := tracker.GetOrCreateCall("completed", layers.LinkTypeEthernet)
	require.NotNil(t, call)
	call.SetCallInfoState("BYE")

	require.Eventually(t, func() bool {
		_, err := tracker.GetCall(call.CallID)
		return err != nil
	}, time.Second, 10*time.Millisecond)
	output.mu.Lock()
	defer output.mu.Unlock()
	require.Equal(t, []string{"completed"}, output.closed)
}
