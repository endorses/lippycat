package capture

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
)

func readinessHandle(t *testing.T) *pcap.Handle {
	t.Helper()
	f := createTestPcapFile(t, 1)
	path := f.Name()
	require.NoError(t, f.Close())
	t.Cleanup(func() { require.NoError(t, os.Remove(path)) })
	handle, err := pcap.OpenOffline(path)
	require.NoError(t, err)
	t.Cleanup(handle.Close)
	return handle
}

func TestCaptureReadinessGatesAllInterfacesAndClosesFailedGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	buffer := NewPacketBuffer(ctx, 8)
	defer buffer.Close()
	handle := readinessHandle(t)
	pending := &pendingCaptureInterface{entered: make(chan struct{}), release: make(chan struct{})}
	ready := make(chan error, 1)
	done := make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		InitWithBufferReady(ctx, []pcaptypes.PcapInterface{&mockPcapInterface{name: "ready", handle: handle}, pending}, "udp", buffer, func(_ []layers.LinkType, err error) {
			calls.Add(1)
			ready <- err
		})
	}()
	<-pending.entered
	select {
	case err := <-ready:
		t.Fatalf("premature readiness: %v", err)
	case packet := <-buffer.Receive():
		t.Fatalf("partial interface generation captured a packet: %s", packet.Interface)
	case <-time.After(30 * time.Millisecond):
	}
	close(pending.release)
	require.Error(t, <-ready)
	<-done
	require.EqualValues(t, 1, calls.Load())
	_, _, err := handle.ReadPacketData()
	require.ErrorIs(t, err, io.EOF, "successful peer handle must close when any interface fails")
	require.False(t, buffer.IsClosed(), "the external owner retains buffer ownership")
}

func TestCaptureReadinessRejectsFilterAndReportsActualLinkType(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid", true: "valid"}[valid], func(t *testing.T) {
			buffer := NewPacketBuffer(t.Context(), 8)
			defer buffer.Close()
			handle := readinessHandle(t)
			filter := "udp and SECRET_INVALID_SELECTOR ("
			if valid {
				filter = "udp"
			}
			called := 0
			InitWithBufferReady(t.Context(), []pcaptypes.PcapInterface{&mockPcapInterface{name: "offline-test", handle: handle}}, filter, buffer, func(links []layers.LinkType, err error) {
				called++
				if valid {
					require.NoError(t, err)
					require.Equal(t, []layers.LinkType{layers.LinkTypeEthernet}, links)
				} else {
					require.Error(t, err)
					require.NotContains(t, err.Error(), "SECRET")
					require.Empty(t, links)
				}
			})
			require.Equal(t, 1, called)
		})
	}
}

func TestCaptureReadinessRejectsEmptyNilAndFailedInterfaces(t *testing.T) {
	for _, ifaces := range [][]pcaptypes.PcapInterface{nil, {nil}, {&mockPcapInterface{name: "synthetic", setError: errors.New("SECRET")}}} {
		buffer := NewPacketBuffer(t.Context(), 1)
		calls := 0
		InitWithBufferReady(t.Context(), ifaces, "", buffer, func(_ []layers.LinkType, err error) {
			calls++
			require.Error(t, err)
			require.NotContains(t, err.Error(), "SECRET")
		})
		require.Equal(t, 1, calls)
		buffer.Close()
	}
}

func TestCaptureReadinessClosesPartialHandleOnSetupError(t *testing.T) {
	buffer := NewPacketBuffer(t.Context(), 1)
	defer buffer.Close()
	handle := readinessHandle(t)
	iface := &mockPcapInterface{name: "partial", handle: handle, setError: errors.New("setup failed")}
	InitWithBufferReady(t.Context(), []pcaptypes.PcapInterface{iface}, "udp", buffer, func(_ []layers.LinkType, err error) { require.Error(t, err) })
	_, _, err := handle.ReadPacketData()
	require.ErrorIs(t, err, io.EOF)
}

func TestCaptureSkipsHandleMetadataAfterCancellation(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "unprepared", true: "prepared"}[prepared], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			handle := readinessHandle(t)
			iface := &mockPcapInterface{name: "cancelled", handle: handle}
			buffer := NewPacketBuffer(ctx, 1)
			defer buffer.Close()
			cancel()
			handle.Close()
			var handleMu sync.Mutex
			// Shutdown won before the reader started. Metadata/filter calls on
			// this closed handle would race with Close or crash inside libpcap.
			if prepared {
				captureFromPreparedHandle(ctx, iface, handle, buffer, nil, nil, nil, &handleMu)
			} else {
				captureFromInterface(ctx, iface, "udp", buffer, nil, nil, nil, &handleMu)
			}
		})
	}
}
