//go:build hunter || all

package capture

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	capturepkg "github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

type admissionRestartInterface struct {
	path   string
	handle *pcap.Handle
}

func (d *admissionRestartInterface) Name() string                  { return "admission-test" }
func (d *admissionRestartInterface) Handle() (*pcap.Handle, error) { return d.handle, nil }
func (d *admissionRestartInterface) SetHandle() (err error) {
	d.handle, err = pcap.OpenOffline(d.path)
	return err
}

type admissionRestartInstaller struct {
	mu                          sync.Mutex
	version                     atomic.Uint64
	fail                        atomic.Bool
	prepared, activated, closed int
	versions                    []uint64
	last                        *pcap.Handle
}

func (i *admissionRestartInstaller) Prepare(_ context.Context, handle *pcap.Handle, _, _ string) (capturepkg.PreparedFilter, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.last != nil {
		if err := i.last.SetBPFFilter("udp"); !errors.Is(err, io.EOF) {
			return nil, errors.New("old reader was not closed before reattachment")
		}
	}
	i.last = handle
	i.prepared++
	if i.fail.Load() {
		return nil, errors.New("injected attachment failure")
	}
	return &admissionRestartAttachment{installer: i}, nil
}

type admissionRestartAttachment struct{ installer *admissionRestartInstaller }

func (a *admissionRestartAttachment) Activate() error {
	a.installer.mu.Lock()
	defer a.installer.mu.Unlock()
	a.installer.activated++
	a.installer.versions = append(a.installer.versions, a.installer.version.Load())
	return nil
}
func (a *admissionRestartAttachment) Close() error {
	a.installer.mu.Lock()
	defer a.installer.mu.Unlock()
	a.installer.closed++
	return nil
}

func TestAdmissionRestartReattachesCurrentPolicyBeforeReadiness(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "capture-*.pcap")
	require.NoError(t, err)
	require.NoError(t, pcapgo.NewWriter(file).WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, file.Close())
	installer := &admissionRestartInstaller{}
	installer.version.Store(1)
	manager := New(Config{BufferSize: 8, FilterInstaller: installer, CaptureInterfaces: func() []pcaptypes.PcapInterface {
		return []pcaptypes.PcapInterface{&admissionRestartInterface{path: file.Name()}}
	}}, t.Context())
	t.Cleanup(manager.Stop)
	require.NoError(t, manager.Start(nil))
	<-manager.captureDone
	buffer := manager.packetBuffer
	installer.version.Store(2) // Policy updates do not themselves recreate capture.
	installer.mu.Lock()
	require.Equal(t, 1, installer.prepared)
	installer.mu.Unlock()
	require.NoError(t, manager.Restart(nil))
	<-manager.captureDone
	require.Same(t, buffer, manager.packetBuffer)
	installer.mu.Lock()
	require.Equal(t, []uint64{1, 2}, installer.versions, "readiness must follow activation against current policy")
	require.Equal(t, 2, installer.closed)
	installer.mu.Unlock()
	installer.fail.Store(true)
	require.ErrorContains(t, manager.Restart(nil), "injected attachment failure")
	select {
	case <-manager.captureDone:
	default:
		t.Fatal("failed replacement returned before partial generation stopped")
	}
	installer.mu.Lock()
	require.Equal(t, 3, installer.prepared)
	require.Equal(t, 2, installer.activated, "failed attachment must never activate")
	installer.mu.Unlock()
}
