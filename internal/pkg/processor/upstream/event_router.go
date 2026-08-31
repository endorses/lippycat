package upstream

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	MaxAge         time.Duration
	Policy         eventspool.ExhaustionPolicy
	Profile        eventsv1.IngressProfile
}

type EventRouter struct {
	mu      sync.Mutex
	manager *Manager
	config  EventRouterConfig
	routes  map[string]*eventRoute
	ctx     context.Context
	cancel  context.CancelFunc
}

type eventRoute struct {
	sink     *eventforwarding.Sink
	spool    *eventspool.Spool
	cancel   context.CancelFunc
	retiring bool
}

func NewEventRouter(manager *Manager, config EventRouterConfig) (*EventRouter, error) {
	if manager == nil || config.SpoolDirectory == "" {
		return nil, fmt.Errorf("new upstream event router: manager and spool directory are required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &EventRouter{manager: manager, config: config, routes: make(map[string]*eventRoute), ctx: ctx, cancel: cancel}
	if err := r.loadExisting(); err != nil {
		cancel()
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
			spool, err := eventspool.Open(eventspool.Config{Directory: dir, MaxBytes: r.config.MaxBytes, MaxAge: r.config.MaxAge, Policy: r.config.Policy})
			if err != nil {
				return err
			}
			source, session, _, lastBatch, err := spool.RecoveryState()
			if err != nil {
				return err
			}
			if session == "" {
				continue
			}
			route, err := r.routeFromSpool(source, session, lastBatch, spool)
			if err != nil {
				return err
			}
			r.routes[source+"\x00"+session] = route
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
	key := env.NodeID + "\x00" + env.ProducerSessionID
	r.mu.Lock()
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
	if route.retiring {
		r.mu.Unlock()
		return fmt.Errorf("route upstream event: producer session is retiring")
	}
	r.mu.Unlock()
	return route.sink.HandleEvent(ctx, event)
}

func (r *EventRouter) newRoute(nodeID, sessionID string) (*eventRoute, error) {
	dir := filepath.Join(r.config.SpoolDirectory, safePathPart(nodeID), safePathPart(sessionID))
	spool, err := eventspool.Open(eventspool.Config{Directory: dir, MaxBytes: r.config.MaxBytes, MaxAge: r.config.MaxAge, Policy: r.config.Policy})
	if err != nil {
		return nil, err
	}
	source, session, _, lastBatch, err := spool.RecoveryState()
	if err != nil {
		return nil, err
	}
	if session != "" && (source != nodeID || session != sessionID) {
		return nil, fmt.Errorf("upstream event spool identity mismatch")
	}
	return r.routeFromSpool(nodeID, sessionID, lastBatch, spool)
}

func (r *EventRouter) routeFromSpool(nodeID, sessionID string, lastBatch uint64, spool *eventspool.Spool) (*eventRoute, error) {
	client, err := eventforwarding.New(eventforwarding.Config{SourceNodeID: nodeID, ProducerSessionID: sessionID, EventAPIMajor: 1, SemanticProfileRevision: 1, EventKinds: []eventsv1.EventKind{1, 2, 3, 4, 5, 6}, Profile: r.config.Profile, RelayNodeID: r.manager.config.ProcessorID}, spool)
	if err != nil {
		return nil, err
	}
	sink, err := eventforwarding.NewSink(client, lastBatch+1, 1)
	if err != nil {
		return nil, err
	}
	routeCtx, cancel := context.WithCancel(r.ctx)
	go r.serve(routeCtx, client)
	return &eventRoute{sink: sink, spool: spool, cancel: cancel}, nil
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
	key := nodeID + "\x00" + sessionID
	r.mu.Lock()
	route := r.routes[key]
	if route == nil {
		r.mu.Unlock()
		return nil
	}
	route.retiring = true
	r.mu.Unlock()
	if err := route.sink.Flush(ctx); err != nil {
		return fmt.Errorf("flush retiring upstream event route: %w", err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for route.spool.Bytes() != 0 {
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
	return nil
}

func (r *EventRouter) Close(context.Context) error { r.cancel(); return nil }

func safePathPart(value string) string {
	return strings.Map(func(ch rune) rune {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' {
			return ch
		}
		return '_'
	}, value)
}

var _ events.Sink = (*EventRouter)(nil)
