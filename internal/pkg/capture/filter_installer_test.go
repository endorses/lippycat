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
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
)

type testFilterInstaller struct {
	prepare func(context.Context, *pcap.Handle, string, string) (PreparedFilter, error)
}

func (f testFilterInstaller) Prepare(ctx context.Context, h *pcap.Handle, name, filter string) (PreparedFilter, error) {
	return f.prepare(ctx, h, name, filter)
}

type testPreparedFilter struct {
	activate func() error
	close    func() error
}

func (f *testPreparedFilter) Activate() error { return f.activate() }
func (f *testPreparedFilter) Close() error    { return f.close() }

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
		return &testPreparedFilter{activate: func() error {
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
