package capture

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
)

type pendingCaptureInterface struct {
	entered chan struct{}
	release chan struct{}
}

func (p *pendingCaptureInterface) SetHandle() error {
	close(p.entered)
	<-p.release
	return fmt.Errorf("test capture setup stopped")
}
func (p *pendingCaptureInterface) Handle() (*pcap.Handle, error) {
	return nil, fmt.Errorf("test capture has no handle")
}
func (p *pendingCaptureInterface) Name() string { return "pending-capture" }

func TestInitWithBufferWaitsForExternalCaptureCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	buffer := NewPacketBuffer(context.Background(), 8)
	defer buffer.Close()
	iface := &pendingCaptureInterface{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(iface.release) })
	done := make(chan struct{})
	go func() {
		defer close(done)
		InitWithBuffer(ctx, []pcaptypes.PcapInterface{iface}, "", buffer, nil, nil)
	}()
	select {
	case <-iface.entered:
	case <-time.After(time.Second):
		t.Fatal("capture setup did not start")
	}
	// A capture generation is unfinished while a reader is still starting or
	// stopping. Cancellation alone must not publish handle completion.
	for _, stopping := range []bool{false, true} {
		if stopping {
			cancel()
		}
		select {
		case <-done:
			t.Fatalf("capture returned before its reader finished (cancelled=%v)", stopping)
		case <-time.After(20 * time.Millisecond):
		}
	}
	release.Do(func() { close(iface.release) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture did not return after reader completion")
	}
	require.False(t, buffer.IsClosed(), "capture must retain caller ownership of the buffer")
}
