package capture

import (
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

type testFilterInstaller struct {
	prepare func(context.Context, *pcap.Handle, string, string) (PreparedFilter, error)
	observe func(string, []byte)
}

func (f testFilterInstaller) RecordObservedPacket(name string, frame []byte) {
	if f.observe != nil {
		f.observe(name, frame)
	}
}

func (f testFilterInstaller) Prepare(ctx context.Context, h *pcap.Handle, name, filter string) (PreparedFilter, error) {
	return f.prepare(ctx, h, name, filter)
}

type testPreparedFilter struct {
	discarded uint64
	activate  func() error
	close     func() error
}

func (f *testPreparedFilter) Activate() error         { return f.activate() }
func (f *testPreparedFilter) Close() error            { return f.close() }
func (f *testPreparedFilter) StartupDiscards() uint64 { return f.discarded }

func TestSocketFilterStartupPreparesAllBeforeActivation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	buffer := NewPacketBuffer(ctx, 8)
	defer buffer.Close()
	handles := []*pcap.Handle{readinessHandle(t), readinessHandle(t)}
	entered := make(chan struct{})
	release := make(chan struct{})
	var prepared, activated, closed atomic.Int32
	installer := testFilterInstaller{prepare: func(ctx context.Context, h *pcap.Handle, name, filter string) (PreparedFilter, error) {
		if name == "second" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		prepared.Add(1)
		// Preparation, rather than the reader's wall clock, owns queue retirement.
		var discarded uint64
		for {
			_, _, err := h.ReadPacketData()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			discarded++
		}
		return &testPreparedFilter{discarded: discarded, activate: func() error {
			if prepared.Load() != 2 {
				return errors.New("activated before all interfaces prepared")
			}
			activated.Add(1)
			return nil
		}, close: func() error {
			_, _, err := h.ReadPacketData()
			if !errors.Is(err, io.EOF) {
				return errors.New("attachment closed before capture handle")
			}
			closed.Add(1)
			return nil
		}}, nil
	}}
	ready := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		InitWithBufferReady(ctx, []pcaptypes.PcapInterface{
			&mockPcapInterface{name: "first", handle: handles[0]}, &mockPcapInterface{name: "second", handle: handles[1]},
		}, "SECRET INVALID CLASSIC FILTER (", buffer, func(_ []layers.LinkType, err error) { ready <- err }, CaptureOptions{FilterInstaller: installer})
	}()
	<-entered
	require.Zero(t, activated.Load())
	select {
	case err := <-ready:
		t.Fatalf("premature readiness: %v", err)
	default:
	}
	close(release)
	require.NoError(t, <-ready, "custom installer must replace, not follow, classic SetBPFFilter")
	<-done
	require.EqualValues(t, 2, activated.Load())
	require.EqualValues(t, 2, closed.Load())
	select {
	case packet := <-buffer.Receive():
		t.Fatalf("pre-attachment packet escaped startup boundary: %v", packet)
	default:
	}
}

func TestSocketFilterPreparedReaderPreservesClockRollback(t *testing.T) {
	// The installer guarantees retirement. Post-activation frames may legitimately
	// have older or unordered host timestamps and must not be discarded by time.
	sample := readinessHandle(t)
	data, _, err := sample.ReadPacketData()
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "clock-*.pcap")
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	timestamps := []time.Time{time.Now().Add(-time.Hour), time.Now().Add(-2 * time.Hour)}
	for _, timestamp := range timestamps {
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(data), Length: len(data)}, data))
	}
	require.NoError(t, file.Close())
	handle, err := pcap.OpenOffline(file.Name())
	require.NoError(t, err)
	t.Cleanup(handle.Close)
	buffer := NewPacketBuffer(t.Context(), 8)
	defer buffer.Close()
	observed := make(chan []byte, 2)
	installer := testFilterInstaller{observe: func(name string, frame []byte) {
		if name == "synthetic" {
			observed <- append([]byte(nil), frame...)
		}
	}, prepare: func(context.Context, *pcap.Handle, string, string) (PreparedFilter, error) {
		return &testPreparedFilter{activate: func() error { return nil }, close: func() error { return nil }}, nil
	}}
	InitWithBufferReady(t.Context(), []pcaptypes.PcapInterface{&mockPcapInterface{name: "synthetic", handle: handle}}, "", buffer,
		func(_ []layers.LinkType, err error) { require.NoError(t, err) }, CaptureOptions{FilterInstaller: installer})
	for _, timestamp := range timestamps {
		select {
		case packet := <-buffer.Receive():
			require.WithinDuration(t, timestamp, packet.Packet.Metadata().Timestamp, time.Microsecond)
		case <-time.After(time.Second):
			t.Fatal("post-activation frame with older timestamp was lost")
		}
		require.Equal(t, data, <-observed, "each original frame supplies exactly one identity observation")
	}
	require.Empty(t, observed)
}

func TestShadowObservationSkipsTruncatedCaptureWithoutDroppingOutput(t *testing.T) {
	sample := readinessHandle(t)
	data, _, err := sample.ReadPacketData()
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "shadow-completeness-*.pcap")
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for _, originalLength := range []int{len(data), len(data) + 300} {
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: originalLength}, data))
	}
	require.NoError(t, file.Close())
	handle, err := pcap.OpenOffline(file.Name())
	require.NoError(t, err)
	t.Cleanup(handle.Close)
	buffer := NewPacketBuffer(t.Context(), 8)
	defer buffer.Close()
	observed := make(chan []byte, 2)
	installer := testFilterInstaller{
		observe: func(_ string, frame []byte) { observed <- append([]byte(nil), frame...) },
		prepare: func(context.Context, *pcap.Handle, string, string) (PreparedFilter, error) {
			return &testPreparedFilter{activate: func() error { return nil }, close: func() error { return nil }}, nil
		},
	}
	InitWithBufferReady(t.Context(), []pcaptypes.PcapInterface{&mockPcapInterface{name: "synthetic", handle: handle}}, "", buffer,
		func(_ []layers.LinkType, err error) { require.NoError(t, err) }, CaptureOptions{FilterInstaller: installer})
	for i := 0; i < 2; i++ {
		select {
		case packet := <-buffer.Receive():
			require.Equal(t, data, packet.Packet.Data(), "sampling completeness never drops ordinary packet output")
		case <-time.After(time.Second):
			t.Fatal("ordinary capture output was lost")
		}
	}
	require.Len(t, observed, 1, "only the complete original frame supplies correlation evidence")
	require.Equal(t, data, <-observed)
}

func TestSocketFilterStartupFailureUnwindsAllAttachments(t *testing.T) {
	for _, activationFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepare", true: "activate"}[activationFailure], func(t *testing.T) {
			buffer := NewPacketBuffer(t.Context(), 8)
			defer buffer.Close()
			firstPrepared := make(chan struct{})
			var closed atomic.Int32
			installer := testFilterInstaller{prepare: func(_ context.Context, h *pcap.Handle, name, _ string) (PreparedFilter, error) {
				if name == "second" {
					<-firstPrepared
					if !activationFailure {
						return nil, errors.New("injected prepare failure")
					}
				} else {
					close(firstPrepared)
				}
				return &testPreparedFilter{activate: func() error {
					if activationFailure && name == "second" {
						return errors.New("injected activation failure")
					}
					return nil
				}, close: func() error {
					_, _, err := h.ReadPacketData()
					if !errors.Is(err, io.EOF) {
						return errors.New("handle not closed")
					}
					closed.Add(1)
					return nil
				}}, nil
			}}
			var readinessErr error
			InitWithBufferReady(t.Context(), []pcaptypes.PcapInterface{
				&mockPcapInterface{name: "first", handle: readinessHandle(t)}, &mockPcapInterface{name: "second", handle: readinessHandle(t)},
			}, "", buffer, func(_ []layers.LinkType, err error) { readinessErr = err }, CaptureOptions{FilterInstaller: installer})
			require.Error(t, readinessErr)
			expected := int32(1)
			if activationFailure {
				expected = 2
			}
			require.Equal(t, expected, closed.Load())
			select {
			case packet := <-buffer.Receive():
				t.Fatalf("failed startup emitted packet: %v", packet)
			default:
			}
		})
	}
}

func TestSocketFilterLegacyEntryUsesInstallerBarrier(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	buffer := NewPacketBuffer(ctx, 8)
	defer buffer.Close()
	var activated atomic.Bool
	installer := testFilterInstaller{prepare: func(_ context.Context, _ *pcap.Handle, _, _ string) (PreparedFilter, error) {
		return &testPreparedFilter{activate: func() error { activated.Store(true); return nil }, close: func() error { return nil }}, nil
	}}
	InitWithBuffer(ctx, []pcaptypes.PcapInterface{&mockPcapInterface{name: "synthetic", handle: readinessHandle(t)}}, "INVALID (", buffer, nil, nil, CaptureOptions{FilterInstaller: installer})
	require.True(t, activated.Load())
}

func TestSocketAdmissionRejectsOfflineBeforeOpeningHandle(t *testing.T) {
	buffer := NewPacketBuffer(t.Context(), 8)
	defer buffer.Close()
	file := createTestPcapFile(t, 1)
	t.Cleanup(func() { require.NoError(t, os.Remove(file.Name())) })
	require.NoError(t, file.Close())
	device := pcaptypes.CreateOfflineInterface(file)
	installer := testFilterInstaller{prepare: func(context.Context, *pcap.Handle, string, string) (PreparedFilter, error) {
		t.Error("offline input must fail before installer preparation")
		return nil, errors.New("unexpected installer call")
	}}
	var startupErr error
	InitWithBufferReady(t.Context(), []pcaptypes.PcapInterface{device}, "", buffer, func(_ []layers.LinkType, err error) {
		startupErr = err
	}, CaptureOptions{FilterInstaller: installer})
	require.ErrorContains(t, startupErr, "requires live capture")
	handle, err := device.Handle()
	require.Error(t, err)
	require.Nil(t, handle)
}
