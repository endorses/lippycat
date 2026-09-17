package upstream

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventforwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

type EventRouterConfig struct {
	SpoolDirectory string
	MaxBytes       uint64
	MaxRecordBytes uint64
	MaxAge         time.Duration
	Policy         eventspool.ExhaustionPolicy
	Profile        eventsv1.IngressProfile
}

type EventRouter struct {
	mu      sync.Mutex
	manager *Manager
	config  EventRouterConfig
	routes  map[eventRouteKey]*eventRoute
	ctx     context.Context
	cancel  context.CancelFunc
	losses  EventLossStats
	closed  bool
}

// EventLossStats contains cumulative event-forwarding losses by pipeline
// boundary for tap/processor status reporting.
type EventLossStats struct {
	Capture, Analysis, Queue, UnsupportedKind, Transport atomic.Uint64
}

// LossSnapshot is a consistent-enough lock-free cumulative status sample.
type LossSnapshot struct{ Capture, Analysis, Queue, UnsupportedKind, Transport uint64 }

func (r *EventRouter) Losses() LossSnapshot {
	return LossSnapshot{Capture: r.losses.Capture.Load(), Analysis: r.losses.Analysis.Load(), Queue: r.losses.Queue.Load(), UnsupportedKind: r.losses.UnsupportedKind.Load(), Transport: r.losses.Transport.Load()}
}

// HasPendingDurableBatches reports whether any producer route still owns
// unacknowledged spool data. Packet fallback must not strand these batches.
func (r *EventRouter) HasPendingDurableBatches() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, route := range r.routes {
		if route.spool.HasPending() {
			return true
		}
	}
	return false
}

func (r *EventRouter) recordLoss(kind eventsv1.LossKind, count uint64) {
	switch kind {
	case eventsv1.LossKind_LOSS_KIND_CAPTURE:
		r.losses.Capture.Add(count)
	case eventsv1.LossKind_LOSS_KIND_ANALYSIS:
		r.losses.Analysis.Add(count)
	case eventsv1.LossKind_LOSS_KIND_DISPATCH, eventsv1.LossKind_LOSS_KIND_BUFFER:
		r.losses.Queue.Add(count)
	case eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT:
		r.losses.UnsupportedKind.Add(count)
	case eventsv1.LossKind_LOSS_KIND_TRANSPORT:
		r.losses.Transport.Add(count)
	}
}

type eventRouteKey struct {
	nodeID    string
	sessionID string
}

type eventRoute struct {
	sink     *eventforwarding.Sink
	spool    *eventspool.Spool
	cancel   context.CancelFunc
	done     chan struct{}
	retiring bool

	admissionMu  sync.Mutex
	admission    *sync.Cond
	accepting    bool
	active       int
	beforeHandle func()
}

func (r *eventRoute) beginHandle() bool {
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	if !r.accepting {
		return false
	}
	r.active++
	return true
}

func (r *eventRoute) endHandle() {
	r.admissionMu.Lock()
	r.active--
	if r.active == 0 {
		r.admission.Broadcast()
	}
	r.admissionMu.Unlock()
}

func (r *eventRoute) stopAdmission() {
	r.admissionMu.Lock()
	r.accepting = false
	r.retiring = true
	r.admissionMu.Unlock()
}

func (r *eventRoute) waitForHandlers() {
	r.admissionMu.Lock()
	for r.active != 0 {
		r.admission.Wait()
	}
	r.admissionMu.Unlock()
}

func NewEventRouter(manager *Manager, config EventRouterConfig) (*EventRouter, error) {
	if manager == nil || config.SpoolDirectory == "" {
		return nil, fmt.Errorf("new upstream event router: manager and spool directory are required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &EventRouter{manager: manager, config: config, routes: make(map[eventRouteKey]*eventRoute), ctx: ctx, cancel: cancel}
	if err := r.loadExisting(); err != nil {
		cancel()
		_ = r.closeRoutes(context.Background())
		return nil, err
	}
	return r, nil
}

func (r *EventRouter) loadExisting() error {
	nodes, err := os.ReadDir(r.config.SpoolDirectory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read upstream event spool: %w", err)
	}
	for _, node := range nodes {
		if !node.IsDir() {
			continue
		}
		sessions, err := os.ReadDir(filepath.Join(r.config.SpoolDirectory, node.Name()))
		if err != nil {
			return err
		}
		for _, sessionDir := range sessions {
			if !sessionDir.IsDir() {
				continue
			}
			dir := filepath.Join(r.config.SpoolDirectory, node.Name(), sessionDir.Name())
			spool, err := eventspool.Open(eventspool.Config{Directory: dir, MaxBytes: r.config.MaxBytes, MaxRecordBytes: r.config.MaxRecordBytes, MaxAge: r.config.MaxAge, Policy: r.config.Policy})
			if err != nil {
				return err
			}
			source, session, _, lastBatch, err := spool.RecoveryState()
			if err != nil {
				return errors.Join(err, spool.Close())
			}
			if session == "" {
				if err := spool.Close(); err != nil {
					return err
				}
				continue
			}
			key := eventRouteKey{nodeID: source, sessionID: session}
			if _, exists := r.routes[key]; exists {
				return errors.Join(fmt.Errorf("duplicate upstream event spool for producer %q session %q", source, session), spool.Close())
			}
			route, err := r.routeFromSpool(source, session, lastBatch, spool)
			if err != nil {
				return err
			}
			r.routes[key] = route
		}
	}
	return nil
}

func (r *EventRouter) HandleEvent(ctx context.Context, event events.Event) error {
	if !r.manager.ForwardingEvents() {
		return nil
	}
	if event == nil {
		return fmt.Errorf("route upstream event: nil event")
	}
	env := event.Envelope()
	if env.NodeID == "" || env.ProducerSessionID == "" || env.EventSequence == 0 {
		return fmt.Errorf("route upstream event: delivery identity is required")
	}
	key := eventRouteKey{nodeID: env.NodeID, sessionID: env.ProducerSessionID}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return fmt.Errorf("route upstream event: router is closed")
	}
	route := r.routes[key]
	if route == nil {
		var err error
		route, err = r.newRoute(env.NodeID, env.ProducerSessionID)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		r.routes[key] = route
	}
	if !route.beginHandle() {
		r.mu.Unlock()
		return fmt.Errorf("route upstream event: producer session is retiring")
	}
	r.mu.Unlock()
	defer route.endHandle()
	if route.beforeHandle != nil {
		route.beforeHandle()
	}
	return route.sink.HandleEvent(ctx, event)
}

func (r *EventRouter) newRoute(nodeID, sessionID string) (*eventRoute, error) {
	dir := filepath.Join(r.config.SpoolDirectory, identityPathPart(nodeID), identityPathPart(sessionID))
	spool, err := eventspool.Open(eventspool.Config{Directory: dir, MaxBytes: r.config.MaxBytes, MaxRecordBytes: r.config.MaxRecordBytes, MaxAge: r.config.MaxAge, Policy: r.config.Policy})
	if err != nil {
		return nil, err
	}
	source, session, _, lastBatch, err := spool.RecoveryState()
	if err != nil {
		return nil, errors.Join(err, spool.Close())
	}
	if session != "" && (source != nodeID || session != sessionID) {
		return nil, errors.Join(fmt.Errorf("upstream event spool identity mismatch"), spool.Close())
	}
	return r.routeFromSpool(nodeID, sessionID, lastBatch, spool)
}

func (r *EventRouter) routeFromSpool(nodeID, sessionID string, lastBatch uint64, spool *eventspool.Spool) (*eventRoute, error) {
	if lastBatch == ^uint64(0) {
		return nil, errors.Join(errors.New("upstream event spool batch sequence is exhausted; rotate the producer session"), spool.Close())
	}
	if err := spool.BindSessionPolicy(r.sessionPolicy(nodeID, sessionID)); err != nil {
		return nil, errors.Join(fmt.Errorf("bind upstream event route session policy: %w", err), spool.Close())
	}
	client, err := eventforwarding.New(eventforwarding.Config{SourceNodeID: nodeID, ProducerSessionID: sessionID, EventAPIMajor: 1, SemanticProfileRevision: 1, EventKinds: []eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}, Profile: r.config.Profile, RelayNodeID: r.manager.config.ProcessorID, OnLoss: r.recordLoss}, spool)
	if err != nil {
		return nil, errors.Join(err, spool.Close())
	}
	sink, err := eventforwarding.NewSink(client, lastBatch+1, 1)
	if err != nil {
		return nil, errors.Join(err, spool.Close())
	}
	routeCtx, cancel := context.WithCancel(r.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.serve(routeCtx, client)
	}()
	route := &eventRoute{sink: sink, spool: spool, cancel: cancel, done: done, accepting: true}
	route.admission = sync.NewCond(&route.admissionMu)
	return route, nil
}

func (r *EventRouter) sessionPolicy(nodeID, sessionID string) eventspool.SessionPolicy {
	deliveryProfile := "reliable"
	if r.config.Profile == eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY {
		deliveryProfile = "memory_only"
	}
	return eventspool.SessionPolicy{
		Version: 1, SourceNodeID: nodeID, ProducerSessionID: sessionID,
		DeliveryProfile: deliveryProfile, IncludeHTTPHeaders: false, SemanticRevision: 1,
	}
}

func (r *EventRouter) serve(ctx context.Context, client *eventforwarding.Client) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !r.manager.ForwardingEvents() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		service := r.manager.eventServiceClient()
		if service == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		stream, err := service.StreamEvents(ctx)
		if err == nil {
			err = client.Serve(ctx, stream)
		}
		if err != nil && ctx.Err() == nil {
			logger.Warn("Upstream event route disconnected", "error", err)
			r.manager.MarkDisconnected()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (r *EventRouter) Flush(ctx context.Context) error {
	r.mu.Lock()
	routes := make([]*eventforwarding.Sink, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route.sink)
	}
	r.mu.Unlock()

	var errs []error
	for _, sink := range routes {
		if err := sink.Flush(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DrainAndRetire flushes terminal loss reports, waits until the upstream has
// cumulatively acknowledged every durable batch, and removes the fixed-session
// route. Once retirement starts, the old session rejects new events.
func (r *EventRouter) DrainAndRetire(ctx context.Context, nodeID, sessionID string) error {
	key := eventRouteKey{nodeID: nodeID, sessionID: sessionID}
	r.mu.Lock()
	route := r.routes[key]
	if route == nil {
		r.mu.Unlock()
		return nil
	}
	route.stopAdmission()
	r.mu.Unlock()
	route.waitForHandlers()
	if err := route.sink.Flush(ctx); err != nil {
		return fmt.Errorf("flush retiring upstream event route: %w", err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for route.spool.HasPending() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("drain retiring upstream event route: %w", ctx.Err())
		case <-ticker.C:
		}
	}
	r.mu.Lock()
	if r.routes[key] == route {
		delete(r.routes, key)
	}
	r.mu.Unlock()
	route.cancel()
	<-route.done
	return route.spool.Close()
}

func (r *EventRouter) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	routes := make([]*eventRoute, 0, len(r.routes))
	for _, route := range r.routes {
		route.stopAdmission()
		routes = append(routes, route)
	}
	r.mu.Unlock()
	for _, route := range routes {
		route.waitForHandlers()
	}
	flushErr := r.Flush(ctx)
	r.cancel()
	return errors.Join(flushErr, r.closeRoutes(ctx))
}

func (r *EventRouter) closeRoutes(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	routes := make([]*eventRoute, 0, len(r.routes))
	for key, route := range r.routes {
		route.stopAdmission()
		routes = append(routes, route)
		delete(r.routes, key)
	}
	r.mu.Unlock()
	for _, route := range routes {
		route.waitForHandlers()
		route.cancel()
	}
	var errs []error
	for _, route := range routes {
		<-route.done
		if err := route.spool.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func identityPathPart(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}

var _ events.Sink = (*EventRouter)(nil)
