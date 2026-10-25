//go:build processor || tap || all

package processor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/events"
)

var (
	ErrNoticeCommandClosed   = errors.New("notice command sink is closed")
	ErrNoticeCommandNotReady = errors.New("notice command sink is not started")
	ErrNoticeCommandFull     = errors.New("notice command queue is full")
	ErrNoticeCommandHistory  = errors.New("notice command identity limit reached")
)

type NoticeCommandSinkConfig struct {
	AuthorityNodeID, AuthorityGeneration     string
	QueueSize, MaxIdentities, MaxOutputBytes int
}

type NoticeCommandSinkStats struct {
	Completed, Failed, Dropped, Duplicate, Ignored uint64
	Queued, Identities                             int
}

// NoticeCommandSink is deliberately not an events.Sink. Only a canonical local
// emission callback may invoke HandleLocalNotice; wire authority strings do not
// prove that a received or replayed notice is eligible for an external action.
type NoticeCommandSink struct {
	mu                 sync.Mutex
	executor           *CommandExecutor
	config             NoticeCommandSinkConfig
	queue              chan TunnelingMetadata
	identities         map[string]struct{}
	started            bool
	closed             bool
	queueClosed        bool
	workerDone         bool
	cancel             context.CancelFunc
	done               chan struct{}
	changed            chan struct{}
	admitted, finished uint64
	stats              NoticeCommandSinkStats
}

func NewNoticeCommandSink(executor *CommandExecutor, config NoticeCommandSinkConfig) (*NoticeCommandSink, error) {
	if !executor.HasTunnelingCommand() {
		return nil, errors.New("notice command sink requires a tunneling command")
	}
	if config.AuthorityNodeID == "" || config.AuthorityGeneration == "" || len(config.AuthorityNodeID) > 1024 || len(config.AuthorityGeneration) > 1024 || config.QueueSize <= 0 || config.MaxIdentities <= 0 || config.MaxOutputBytes <= 0 || config.QueueSize > config.MaxIdentities {
		return nil, errors.New("notice command sink requires bounded authority, positive limits, and queue <= identity capacity")
	}
	return &NoticeCommandSink{executor: executor, config: config, queue: make(chan TunnelingMetadata, config.QueueSize), identities: make(map[string]struct{}), done: make(chan struct{}), changed: make(chan struct{})}, nil
}

func (s *NoticeCommandSink) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *NoticeCommandSink) Start(parent context.Context) error {
	if parent == nil {
		return errors.New("notice command sink requires a context")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrNoticeCommandClosed
	}
	if s.started {
		return errors.New("notice command sink is already started")
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel, s.started = cancel, true
	go func() {
		defer cancel()
		s.run(ctx)
	}()
	return nil
}

func noticeCommandMetadata(notice events.NoticeEvent) (TunnelingMetadata, error) {
	env, dns := notice.Envelope(), notice.DNS
	if len(env.NodeID) > 1024 || len(env.ProducerSessionID) > 1024 || len(env.EventID) > 4096 || !events.HasValidDeliveryIdentity(env) || env.Timestamp.IsZero() || notice.SchemaVersion != events.NoticeSchemaVersion || notice.DetectorVersion == "" || dns == nil || dns.Domain == "" || len(dns.Domain) > 253 || dns.Queries == 0 || dns.Queries > math.MaxInt64 || len(dns.SourceIPs) > 4096 {
		return TunnelingMetadata{}, errors.New("notice command requires valid local delivery identity and bounded DNS evidence")
	}
	if math.IsNaN(dns.Score) || math.IsInf(dns.Score, 0) || dns.Score < 0 || dns.Score > 1 || math.IsNaN(dns.Threshold) || math.IsInf(dns.Threshold, 0) || dns.Threshold < 0 || dns.Threshold > 1 || dns.Score < dns.Threshold || math.IsNaN(dns.Entropy) || math.IsInf(dns.Entropy, 0) || dns.Entropy < 0 {
		return TunnelingMetadata{}, errors.New("notice command requires finite triggered DNS score evidence")
	}
	meta := TunnelingMetadata{Domain: dns.Domain, Score: dns.Score, Entropy: dns.Entropy, Queries: int64(dns.Queries), HunterID: env.NodeID, Timestamp: env.Timestamp}
	for _, address := range dns.SourceIPs {
		if !address.IsValid() || address.Zone() != "" {
			return TunnelingMetadata{}, errors.New("notice command source address is invalid")
		}
		meta.SrcIPs = append(meta.SrcIPs, address.String())
	}
	return meta, nil
}

func (s *NoticeCommandSink) HandleLocalNotice(ctx context.Context, notice events.NoticeEvent) error {
	if notice.DetectorNodeID != s.config.AuthorityNodeID || notice.DetectorGeneration != s.config.AuthorityGeneration || notice.Detector != events.NoticeDetectorDNSTunneling || notice.Category != events.NoticeCategorySecurity || notice.Status != events.NoticeTriggered || notice.Severity != events.NoticeWarning {
		s.mu.Lock()
		s.stats.Ignored++
		s.mu.Unlock()
		return nil
	}
	meta, err := noticeCommandMetadata(notice)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.stats.Dropped++
		return err
	}
	if s.closed {
		s.stats.Dropped++
		return ErrNoticeCommandClosed
	}
	if !s.started {
		s.stats.Dropped++
		return ErrNoticeCommandNotReady
	}
	if ctx == nil {
		s.stats.Dropped++
		return errors.New("notice admission requires a context")
	}
	if err := ctx.Err(); err != nil {
		s.stats.Dropped++
		return err
	}
	id := notice.Envelope().EventID
	if _, duplicate := s.identities[id]; duplicate {
		s.stats.Duplicate++
		return nil
	}
	if len(s.identities) >= s.config.MaxIdentities {
		s.stats.Dropped++
		return ErrNoticeCommandHistory
	}
	// Preserve the attempted identity even on queue overflow. A later replay
	// cannot turn a previously rejected action into a newly eligible command.
	s.identities[id] = struct{}{}
	select {
	case s.queue <- meta:
		s.admitted++
		return nil
	default:
		s.stats.Dropped++
		return ErrNoticeCommandFull
	}
}

func (s *NoticeCommandSink) run(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		s.closed, s.workerDone = true, true
		s.notifyLocked()
		close(s.done)
		s.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.closed = true
			for {
				select {
				case _, ok := <-s.queue:
					if !ok {
						s.mu.Unlock()
						return
					}
					s.stats.Dropped++
					s.finished++
				default:
					s.notifyLocked()
					s.mu.Unlock()
					return
				}
			}
		case meta, ok := <-s.queue:
			if !ok {
				return
			}
			err := s.executor.ExecuteTunnelingCommandContext(ctx, meta, s.config.MaxOutputBytes)
			s.mu.Lock()
			s.finished++
			switch {
			case err == nil:
				s.stats.Completed++
			case errors.Is(err, ErrCommandConcurrencyLimit) || ctx.Err() != nil:
				s.stats.Dropped++
			default:
				s.stats.Failed++
			}
			s.notifyLocked()
			s.mu.Unlock()
		}
	}
}

// Flush waits for every action admitted before this call, without stopping later
// local admissions. Completed actions include failed or explicitly dropped work.
func (s *NoticeCommandSink) Flush(ctx context.Context) error {
	if ctx == nil {
		return errors.New("notice flush requires a context")
	}
	s.mu.Lock()
	target := s.admitted
	for s.finished < target {
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
	}
	s.mu.Unlock()
	return nil
}

// Close rejects new actions and drains admitted work. If ctx expires, it cancels
// execution and joins the worker before returning the context error.
func (s *NoticeCommandSink) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("notice close requires a context")
	}
	s.mu.Lock()
	s.closed = true
	if !s.queueClosed {
		close(s.queue)
		s.queueClosed = true
	}
	if !s.started && !s.workerDone {
		s.workerDone = true
		close(s.done)
		s.notifyLocked()
	}
	cancel := s.cancel
	s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		if cancel != nil {
			cancel()
		}
		<-s.done
		return fmt.Errorf("close notice command sink: %w", ctx.Err())
	}
}

func (s *NoticeCommandSink) Stats() NoticeCommandSinkStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.stats
	stats.Queued, stats.Identities = len(s.queue), len(s.identities)
	return stats
}
