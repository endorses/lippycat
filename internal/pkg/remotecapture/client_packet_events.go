package remotecapture

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// packetEventAnalysis belongs to one packet subscription. Packet-only nodes
// delegate Events-view analysis to the monitoring client; authoritative remote
// events continue to arrive independently through SubscribeEvents.
type packetEventAnalysis struct {
	client     *Client
	ctx        context.Context
	generation uint64
	runtime    *eventanalysis.Runtime
	dispatcher *events.Dispatcher
}

func (a *packetEventAnalysis) active() bool {
	return a.ctx.Err() == nil && a.client.ctx.Err() == nil && a.client.isCurrentEventStream(a.generation)
}

func (a *packetEventAnalysis) start() error {
	producer, err := events.NewLiveProducerSet()
	if err != nil {
		return fmt.Errorf("create monitoring event identity: %w", err)
	}
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 1024, SinkQueueSize: 1024, Producer: producer})
	if err != nil {
		return fmt.Errorf("create monitoring event dispatcher: %w", err)
	}
	if err := dispatcher.Register(&packetEventSink{analysis: a}); err != nil {
		return fmt.Errorf("register monitoring event sink: %w", err)
	}
	runtime, err := eventanalysis.New(eventanalysis.Config{Dispatcher: dispatcher, LiveExpiry: true})
	if err != nil {
		return fmt.Errorf("create monitoring event analysis: %w", err)
	}
	// Shutdown closes the runtime before draining the dispatcher. Its context
	// must outlive subscription cancellation so that both can release their state.
	if err := dispatcher.Start(context.Background()); err != nil {
		runtime.Close()
		return fmt.Errorf("start monitoring event dispatcher: %w", err)
	}
	a.runtime, a.dispatcher = runtime, dispatcher
	return nil
}

func (a *packetEventAnalysis) observe(batch *data.PacketBatch) error {
	if batch == nil || len(batch.Packets) == 0 || batch.MonitorEventAnalysis != data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_CLIENT_REQUIRED || !a.active() {
		return nil
	}
	if a.runtime == nil {
		if err := a.start(); err != nil {
			return err
		}
	}
	nodeID := batch.HunterId
	if nodeID == "" {
		nodeID = a.client.nodeID
	}
	if nodeID == "" {
		nodeID = a.client.addr
	}
	source := eventanalysis.Source{NodeID: nodeID, CaptureSource: nodeID, CaptureScope: events.CaptureScopeFiltered, Partial: true}
	if a.client.nodeID != "" {
		source.ProcessorNodeIDs = []string{a.client.nodeID}
	}
	var firstErr error
	invalid := 0
	recordError := func(err error) {
		invalid++
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, raw := range batch.Packets {
		if raw == nil {
			continue
		}
		if len(raw.Data) == 0 {
			if err := a.runtime.ObserveCaptured(source, []*data.CapturedPacket{raw}); err != nil {
				recordError(err)
			}
			continue
		}
		packet := gopacket.NewPacket(raw.Data, layers.LinkType(raw.LinkType), gopacket.Default)
		packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(0, raw.TimestampNs), CaptureLength: int(raw.CaptureLength), Length: int(raw.OriginalLength), InterfaceIndex: int(raw.InterfaceIndex)}
		packetSource := source
		packetSource.InterfaceName = raw.InterfaceName
		packetSource.InterfaceIndex = raw.InterfaceIndex
		if err := a.runtime.ObservePacket(packetSource, capture.PacketInfo{Packet: packet, Interface: raw.InterfaceName, LinkType: layers.LinkType(raw.LinkType)}); err != nil {
			recordError(err)
		}
	}
	if firstErr != nil {
		return fmt.Errorf("analyze monitoring packets: %d of %d invalid: %w", invalid, len(batch.Packets), firstErr)
	}
	return nil
}

func (a *packetEventAnalysis) close() {
	if a.runtime == nil {
		return
	}
	a.runtime.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.dispatcher.Close(ctx); err != nil {
		logger.Warn("Failed to close remote monitoring event analysis", "error", err)
	}
}

type packetEventSink struct {
	analysis     *packetEventAnalysis
	dropBoundary sync.Mutex
	dropped      uint64
}

func (s *packetEventSink) Flush(context.Context) error {
	s.deliver(types.EventBatch{})
	return nil
}
func (s *packetEventSink) Close(ctx context.Context) error { return s.Flush(ctx) }

func (s *packetEventSink) LockDropBoundary()                                { s.dropBoundary.Lock() }
func (s *packetEventSink) UnlockDropBoundary()                              { s.dropBoundary.Unlock() }
func (s *packetEventSink) HandleDroppedEventLocked(events.Event, time.Time) { s.dropped++ }

func (s *packetEventSink) deliver(batch types.EventBatch) {
	s.dropBoundary.Lock()
	if s.dropped > 0 {
		batch.Losses = []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_BUFFER, Count: s.dropped}}
		s.dropped = 0
	}
	s.dropBoundary.Unlock()
	if len(batch.Events) == 0 && len(batch.Losses) == 0 {
		return
	}
	// Serialize the final generation check with subscription replacement, so
	// an old dispatch worker cannot deliver into the replacement's event view.
	a := s.analysis
	a.client.eventCursorMu.Lock()
	defer a.client.eventCursorMu.Unlock()
	if a.ctx.Err() == nil && a.client.ctx.Err() == nil && (a.generation == 0 || a.generation == a.client.eventStreamGeneration) {
		a.client.deliverEventBatch(batch)
	}
}

func (s *packetEventSink) HandleEvent(_ context.Context, event events.Event) error {
	s.deliver(types.EventBatch{Events: []events.Event{event}})
	return nil
}
