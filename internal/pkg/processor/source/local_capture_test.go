package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

type localCaptureFixture struct {
	path   string
	handle *pcap.Handle
	err    error
}

func (f *localCaptureFixture) Name() string { return "synthetic-capture" }
func (f *localCaptureFixture) SetHandle() error {
	if f.err != nil {
		return f.err
	}
	var err error
	f.handle, err = pcap.OpenOffline(f.path)
	return err
}
func (f *localCaptureFixture) Handle() (*pcap.Handle, error) { return f.handle, nil }

func installLocalCaptureFixture(t *testing.T, s *LocalSource) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "empty.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, pcapgo.NewWriter(f).WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, f.Close())
	s.config.CaptureInterfaces = func() []pcaptypes.PcapInterface { return []pcaptypes.PcapInterface{&localCaptureFixture{path: path}} }
}

func TestLocalCaptureValidatesSyntaxAndEveryKnownLinkType(t *testing.T) {
	s := NewLocalSource(DefaultLocalSourceConfig())
	defer s.radiusProcessor.Close()
	require.Error(t, s.ValidateBPFFilter("udp and SECRET_INVALID_SELECTOR ("))
	require.NoError(t, s.ValidateBPFFilter("wlan type mgt"), "first-start syntax must allow non-Ethernet capture")
	s.captureLinks = []layers.LinkType{layers.LinkTypeIEEE802_11, layers.LinkTypeEthernet}
	err := s.ValidateBPFFilter("wlan type mgt")
	require.Error(t, err, "all configured link types must support the expression")
	require.NotContains(t, err.Error(), "wlan")
	require.NoError(t, s.ValidateBPFFilter("udp"))
}

func TestLocalCaptureStartupFailureAndUnexpectedExitCloseBatches(t *testing.T) {
	for _, unexpected := range []bool{false, true} {
		t.Run(map[bool]string{false: "open-failure", true: "unexpected-exit"}[unexpected], func(t *testing.T) {
			s := NewLocalSource(LocalSourceConfig{BPFFilter: "udp", BufferSize: 8, BatchBuffer: 1})
			if unexpected {
				installLocalCaptureFixture(t, s)
			} else {
				s.config.CaptureInterfaces = func() []pcaptypes.PcapInterface {
					return []pcaptypes.PcapInterface{&localCaptureFixture{err: errors.New("SECRET interface failure")}}
				}
			}
			done := make(chan error, 1)
			go func() { done <- s.Start(t.Context()) }()
			select {
			case err := <-done:
				require.Error(t, err)
				require.NotContains(t, err.Error(), "SECRET")
			case <-time.After(5 * time.Second):
				t.Fatal("capture startup did not return its failure")
			}
			_, open := <-s.Batches()
			require.False(t, open, "processor shutdown must observe completed local input")
			require.Error(t, s.Start(t.Context()), "a closed source cannot close its channels twice")
		})
	}
}

func TestLocalCaptureReplacementFailsSynchronously(t *testing.T) {
	for _, setup := range []string{"open", "filter"} {
		t.Run(setup, func(t *testing.T) {
			s := NewLocalSource(LocalSourceConfig{BPFFilter: "tcp", BufferSize: 8, BatchBuffer: 1})
			defer s.radiusProcessor.Close()
			s.ctx, s.cancel = context.WithCancel(t.Context())
			defer s.cancel()
			s.started = true
			s.captureDone = make(chan struct{})
			close(s.captureDone)
			filter := "udp"
			if setup == "open" {
				s.config.CaptureInterfaces = func() []pcaptypes.PcapInterface {
					return []pcaptypes.PcapInterface{&localCaptureFixture{err: errors.New("SECRET interface failure")}}
				}
			} else {
				installLocalCaptureFixture(t, s)
				filter = "wlan type mgt" // Generic syntax is valid; the actual Ethernet handle rejects it.
			}
			pb := capture.NewPacketBuffer(s.ctx, 8)
			s.packetBuffer.Store(pb)
			defer pb.Close()
			err := s.SetBPFFilter(filter)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "SECRET")
			require.Equal(t, "tcp", s.config.BPFFilter, "failed replacement must not masquerade as applied")
			s.wg.Wait()
		})
	}
}

func TestLocalCapturePolicyBoundaryReportsFailedReplacement(t *testing.T) {
	s := NewLocalSource(LocalSourceConfig{BPFFilter: "tcp", BufferSize: 8, BatchBuffer: 1})
	defer s.radiusProcessor.Close()
	s.ctx, s.cancel = context.WithCancel(t.Context())
	defer s.cancel()
	s.started = true
	s.captureDone = make(chan struct{})
	close(s.captureDone)
	s.batchingDone = make(chan struct{})
	close(s.batchingDone)
	installLocalCaptureFixture(t, s)
	pb := capture.NewPacketBuffer(s.ctx, 8)
	s.packetBuffer.Store(pb)
	defer pb.Close()
	processed := make(chan struct{})
	go func() {
		defer close(processed)
		batch := <-s.batches
		batch.RunAfterProcess()
	}()
	applied := false
	err := s.ApplyPolicyBoundary(t.Context(), "wlan type mgt", func() error { applied = true; return nil })
	require.Error(t, err)
	require.True(t, applied, "post-commit application failure must be visible after the boundary")
	require.Equal(t, "tcp", s.config.BPFFilter)
	require.True(t, s.packetBuffer.Load().IsClosed(), "failed replacement must release the new buffer merger")
	<-processed
	s.wg.Wait()
}
