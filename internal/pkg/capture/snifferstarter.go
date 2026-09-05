package capture

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
)

func StartLiveSniffer(interfaces, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string)) {
	var devices []pcaptypes.PcapInterface
	for _, device := range strings.Split(interfaces, ",") {
		iface := pcaptypes.CreateLiveInterface(device)
		devices = append(devices, iface)
	}
	startSniffer(devices, filter)
}

// StartOfflineSnifferOrdered opens PCAP files and starts a timestamp-ordered sniffer.
// This ensures packets from multiple files are processed in chronological order,
// which is essential for VoIP analysis where SIP signaling must precede RTP.
func StartOfflineSnifferOrdered(readFiles []string, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string)) (err error) {
	if len(readFiles) == 0 {
		return errors.New("no files provided for offline capture")
	}
	if len(readFiles) > MaxOfflineSources {
		return fmt.Errorf("offline capture supports at most %d sources; use fewer input files", MaxOfflineSources)
	}
	var files []*os.File
	var devices []pcaptypes.PcapInterface
	defer func() {
		for _, f := range files {
			if closeErr := f.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close offline source %q: %w", f.Name(), closeErr))
			}
		}
		if err != nil {
			logger.Error("Offline capture failed", "error", err)
		}
	}()
	for _, readFile := range readFiles {
		info, statErr := os.Stat(readFile)
		if statErr != nil {
			return fmt.Errorf("stat offline source %q: %w", readFile, statErr)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("offline source %q must be a regular capture file", readFile)
		}
		// #nosec G304 -- intentional user-specified capture path
		file, openErr := os.Open(readFile)
		if openErr != nil {
			return fmt.Errorf("open offline source %q: %w", readFile, openErr)
		}
		files = append(files, file)
		devices = append(devices, pcaptypes.CreateOfflineInterface(file))
	}
	startSniffer(devices, filter)
	return nil
}

// RunWithSignalHandler runs the capture in background and handles signals for graceful shutdown
// This is the common pattern used by hunt, sniff, and sniff voip commands
func RunWithSignalHandler(devices []pcaptypes.PcapInterface, filter string,
	processor func(<-chan PacketInfo)) {

	// Create cancellable context for capture
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handler for graceful shutdown
	cleanup := signals.SetupHandler(ctx, cancel)
	defer cleanup()

	// Channel to signal when capture exits (for early exit on capture failure)
	captureDone := make(chan struct{})

	// Run capture in background (like hunter nodes do)
	go func() {
		InitWithContext(ctx, devices, filter, func(ch <-chan PacketInfo, _ *TCPAssembler) {
			processor(ch)
		}, nil, nil)
		close(captureDone)
	}()

	// Wait for signal OR capture completion (e.g., all captures failed)
	select {
	case <-ctx.Done():
		// Signal received, wait for capture to finish
		<-captureDone
	case <-captureDone:
		// Capture finished early (likely all captures failed)
		// No need to wait, just exit
	}

	// Give a brief moment for graceful cleanup (like hunt nodes do)
	time.Sleep(constants.SnifferCleanupTimeout)
}

// checkCapturePermissions validates that we can open capture handles on all devices
// Returns true if at least one device is accessible, false if all fail
func checkCapturePermissions(devices []pcaptypes.PcapInterface) bool {
	hasPermission := false
	allFailed := true

	for _, dev := range devices {
		// Try to set the handle (this will fail if insufficient permissions)
		err := dev.SetHandle()
		if err != nil {
			logger.Error("Error setting pcap handle", "error", err, "interface", dev.Name())
			continue
		}

		// Success - at least one device is accessible
		hasPermission = true
		allFailed = false

		// Close the handle immediately - we'll reopen in capture goroutines
		if handle, err := dev.Handle(); err == nil && handle != nil {
			handle.Close()
		}
	}

	if allFailed {
		logger.Error("All capture interfaces failed to start - insufficient permissions")
		return false
	}

	return hasPermission
}

// MaxOfflineSources bounds simultaneously open readers and merge lookahead.
const MaxOfflineSources = 64

// ErrOfflineConsumerStopped reports a consumer returning before input is drained.
var ErrOfflineConsumerStopped = errors.New("offline consumer stopped before draining input")

// RunOfflineOrdered streams files in timestamp order and logs replay failures for
// legacy callers. New session owners should use the error-returning variants.
func RunOfflineOrdered(devices []pcaptypes.PcapInterface, filter string,
	processor func(<-chan PacketInfo)) {
	if err := RunOfflineOrderedContext(context.Background(), devices, filter, processor); err != nil {
		logger.Error("Timestamp-ordered offline capture failed", "error", err)
	}
}

// RunOfflineOrderedContext streams ordered input to a legacy consumer. The
// consumer must return after input closes or the supplied context is cancelled.
func RunOfflineOrderedContext(ctx context.Context, devices []pcaptypes.PcapInterface, filter string,
	processor func(<-chan PacketInfo)) error {
	return RunOfflineOrderedStream(ctx, devices, filter, func(_ context.Context, ch <-chan PacketInfo) error {
		processor(ch)
		return nil
	})
}

// RunOfflineOrderedStream owns and joins the producer and consumer. Consumer
// failure cancels reads and blocked sends; source failure closes input and
// cancels the consumer context. Consumers must honor cancellation or input EOF.
// Records already delivered before an error are partial input, never a completed
// dataset. The caller must discard any unpublished session on failure.
func RunOfflineOrderedStream(ctx context.Context, devices []pcaptypes.PcapInterface, filter string,
	processor func(context.Context, <-chan PacketInfo) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(devices) > MaxOfflineSources {
		return fmt.Errorf("offline capture supports at most %d sources (got %d); use fewer input files", MaxOfflineSources, len(devices))
	}
	parentCtx := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cursors := make([]*offlineCursor, 0, len(devices))
	defer func() {
		for _, cursor := range cursors {
			err = errors.Join(err, cursor.Close())
		}
	}()
	pending := offlinePacketHeap{}
	for i, dev := range devices {
		if err := ctx.Err(); err != nil {
			return err
		}
		cursor, err := newOfflineCursor(ctx, dev, filter, uint32(i))
		if err != nil {
			return err
		}
		cursors = append(cursors, cursor)
		pkt, err := cursor.Next(ctx)
		if errors.Is(err, io.EOF) {
			continue
		}
		if err != nil {
			return err
		}
		heap.Push(&pending, offlineHeapEntry{packet: pkt, source: i})
	}
	packetStream := make(chan PacketInfo)
	consumerDone := make(chan struct{})
	var consumerErr error
	go func() {
		defer close(consumerDone)
		consumerErr = processor(ctx, packetStream)
		cancel()
	}()
	var producerErr error
	for len(pending) > 0 {
		entry := heap.Pop(&pending).(offlineHeapEntry)
		select {
		case <-ctx.Done():
			producerErr = ctx.Err()
		case packetStream <- entry.packet:
			observePacket(entry.packet)
		}
		if producerErr != nil {
			break
		}
		pkt, readErr := cursors[entry.source].Next(ctx)
		if errors.Is(readErr, io.EOF) {
			continue
		}
		if readErr != nil {
			producerErr = readErr
			break
		}
		heap.Push(&pending, offlineHeapEntry{packet: pkt, source: entry.source})
	}
	close(packetStream)
	if producerErr != nil {
		cancel()
	}
	<-consumerDone
	if consumerErr != nil {
		return errors.Join(producerErr, fmt.Errorf("offline consumer: %w", consumerErr))
	}
	if producerErr != nil {
		// A consumer that returns without draining must not strand the producer or
		// make an incomplete replay look successful.
		if errors.Is(producerErr, context.Canceled) && parentCtx.Err() == nil {
			return errors.Join(producerErr, ErrOfflineConsumerStopped)
		}
		return producerErr
	}
	return parentCtx.Err()
}

type offlineHeapEntry struct {
	packet PacketInfo
	source int
}

type offlinePacketHeap []offlineHeapEntry

func (h offlinePacketHeap) Len() int { return len(h) }
func (h offlinePacketHeap) Less(i, j int) bool {
	a, b := h[i].packet.Packet.Metadata().Timestamp, h[j].packet.Packet.Metadata().Timestamp
	if a.Equal(b) {
		return h[i].source < h[j].source
	}
	return a.Before(b)
}
func (h offlinePacketHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *offlinePacketHeap) Push(v any)   { *h = append(*h, v.(offlineHeapEntry)) }
func (h *offlinePacketHeap) Pop() any {
	n := len(*h) - 1
	v := (*h)[n]
	(*h)[n] = offlineHeapEntry{}
	*h = (*h)[:n]
	return v
}

// readAllPacketsFromDevice is a collecting convenience for small test fixtures.
// Production replay uses the cursor directly and never collects the input.
func readAllPacketsFromDevice(dev pcaptypes.PcapInterface, filter string) ([]PacketInfo, error) {
	return readAllPacketsFromDeviceContext(context.Background(), dev, filter)
}

func readAllPacketsFromDeviceContext(ctx context.Context, dev pcaptypes.PcapInterface, filter string) (packets []PacketInfo, err error) {
	cursor, err := newOfflineCursor(ctx, dev, filter, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, cursor.Close()) }()
	for {
		pkt, err := cursor.Next(ctx)
		if errors.Is(err, io.EOF) {
			return packets, nil
		}
		if err != nil {
			return nil, err
		}
		packets = append(packets, pkt)
	}
}
