// Package eventcoalesce combines message-level protocol events into the
// transaction-level records expected by Zeek-style log consumers.
package eventcoalesce

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Config bounds pending transactions. Expired and evicted events are emitted
// as partial records rather than silently discarded.
type Config struct {
	Timeout    time.Duration
	MaxPending int
}

type pending struct {
	event events.Event
	seen  time.Time
}

type dnsKey struct {
	uid      string
	id       uint16
	protocol uint8
}

// Sink wraps an event sink and coalesces HTTP request/response, TLS
// ClientHello/ServerHello, and DNS query/response pairs. All other event kinds
// pass through unchanged.
type Sink struct {
	next events.Sink
	cfg  Config
	mu   sync.Mutex
	http map[string][]pending
	tls  map[string]pending
	dns  map[dnsKey][]pending
	done chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

func New(next events.Sink, cfg Config) (*Sink, error) {
	if next == nil {
		return nil, fmt.Errorf("coalescing sink: nil downstream sink")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 100000
	}
	s := &Sink{next: next, cfg: cfg, http: make(map[string][]pending), tls: make(map[string]pending), dns: make(map[dnsKey][]pending), done: make(chan struct{})}
	s.wg.Add(1)
	go s.expiryLoop()
	return s, nil
}

func (s *Sink) expiryLoop() {
	defer s.wg.Done()
	interval := s.cfg.Timeout / 2
	if interval > time.Second {
		interval = time.Second
	}
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			s.mu.Lock()
			if err := s.expireLocked(context.Background(), now); err != nil {
				logger.Error("Failed to emit expired protocol transaction", "error", err)
			}
			s.mu.Unlock()
		case <-s.done:
			return
		}
	}
}

func (s *Sink) HandleEvent(ctx context.Context, event events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.expireLocked(ctx, time.Now()); err != nil {
		return err
	}
	switch ev := event.(type) {
	case events.DNSEvent:
		return s.dnsLocked(ctx, ev)
	case events.HTTPEvent:
		return s.httpLocked(ctx, ev)
	case events.TLSEvent:
		return s.tlsLocked(ctx, ev)
	default:
		return s.next.HandleEvent(ctx, event)
	}
}

func (s *Sink) dnsLocked(ctx context.Context, ev events.DNSEvent) error {
	key := dnsKey{uid: ev.Envelope().UID, id: ev.TransactionID, protocol: ev.Envelope().Flow.Protocol}
	if !ev.IsResponse {
		s.dns[key] = append(s.dns[key], pending{event: ev, seen: time.Now()})
		return s.enforceLimitLocked(ctx)
	}
	queue := s.dns[key]
	if len(queue) == 0 {
		return s.next.HandleEvent(ctx, ev)
	}
	query := queue[0].event.(events.DNSEvent)
	if len(queue) == 1 {
		delete(s.dns, key)
	} else {
		s.dns[key] = queue[1:]
	}
	mergeDNS(&query, ev)
	return s.next.HandleEvent(ctx, query)
}

func mergeDNS(dst *events.DNSEvent, response events.DNSEvent) {
	dst.RCode = response.RCode
	dst.Authoritative, dst.Truncated = response.Authoritative, response.Truncated
	dst.RecursionAvailable, dst.Z = response.RecursionAvailable, response.Z
	dst.Answers, dst.TTLs, dst.Rejected = response.Answers, response.TTLs, response.Rejected
	if response.Query != "" {
		if dst.Query == "" {
			dst.Query = response.Query
		}
		if dst.QClass == 0 {
			dst.QClass = response.QClass
		}
		if dst.QType == 0 {
			dst.QType = response.QType
		}
	}
	if response.RTT > 0 {
		dst.RTT = response.RTT
	} else if elapsed := response.Envelope().Timestamp.Sub(dst.Envelope().Timestamp); elapsed > 0 {
		dst.RTT = elapsed
	}
}

func (s *Sink) httpLocked(ctx context.Context, ev events.HTTPEvent) error {
	uid := ev.Envelope().UID
	if ev.StatusCode == 0 && ev.InformationalCode == 0 {
		s.http[uid] = append(s.http[uid], pending{event: ev, seen: time.Now()})
		return s.enforceLimitLocked(ctx)
	}
	queue := s.http[uid]
	if len(queue) == 0 {
		return s.next.HandleEvent(ctx, ev)
	}
	request := queue[0].event.(events.HTTPEvent)
	// Keep informational responses attached to the pending request and wait for
	// the final response. Zeek represents both on a single transaction row.
	if ev.StatusCode < 200 && (ev.StatusCode != 0 || ev.InformationalCode != 0) {
		request.InformationalCode = ev.InformationalCode
		request.InformationalMessage = ev.InformationalMessage
		if request.InformationalCode == 0 {
			request.InformationalCode = ev.StatusCode
			request.InformationalMessage = ev.StatusMessage
		}
		queue[0].event = request
		s.http[uid] = queue
		return nil
	}
	if len(queue) == 1 {
		delete(s.http, uid)
	} else {
		s.http[uid] = queue[1:]
	}
	mergeHTTP(&request, ev)
	return s.next.HandleEvent(ctx, request)
}

func mergeHTTP(dst *events.HTTPEvent, response events.HTTPEvent) {
	dst.ResponseBodyLength = response.ResponseBodyLength
	dst.StatusCode, dst.StatusMessage = response.StatusCode, response.StatusMessage
	if response.InformationalCode != 0 {
		dst.InformationalCode, dst.InformationalMessage = response.InformationalCode, response.InformationalMessage
	}
	dst.ResponseFileIDs, dst.ResponseFilenames, dst.ResponseMIMETypes = response.ResponseFileIDs, response.ResponseFilenames, response.ResponseMIMETypes
	if dst.Version == "" {
		dst.Version = response.Version
	}
	if dst.Host == "" {
		dst.Host = response.Host
	}
	if dst.Method == "" {
		dst.Method = response.Method
	}
	if dst.URI == "" {
		dst.URI = response.URI
	}
}

func (s *Sink) tlsLocked(ctx context.Context, ev events.TLSEvent) error {
	// Some capture paths can attach an allocated, but otherwise empty, TLS
	// metadata message to a packet after the real handshake has already been
	// emitted. Treating that message as a ClientHello leaves it pending and
	// later creates a second, empty ssl.log row. It carries no information that
	// a Zeek-style TLS record can use, so discard it here. Deliberately test all
	// TLS fields: genuinely incomplete handshakes (for example, version-only or
	// SNI-only ClientHellos) must still be retained and emitted as partial rows.
	if emptyTLS(ev) {
		return nil
	}
	uid := ev.Envelope().UID
	// ServerHello is identifiable by server-selected fields or establishment.
	isServer := ev.Established || ev.Cipher != "" || ev.JA3S != ""
	if !isServer {
		s.tls[uid] = pending{event: ev, seen: time.Now()}
		return s.enforceLimitLocked(ctx)
	}
	p, ok := s.tls[uid]
	if !ok {
		return s.next.HandleEvent(ctx, ev)
	}
	delete(s.tls, uid)
	client := p.event.(events.TLSEvent)
	mergeTLS(&client, ev)
	return s.next.HandleEvent(ctx, client)
}

func emptyTLS(ev events.TLSEvent) bool {
	return ev.Version == "" && ev.Cipher == "" && ev.Curve == "" && ev.ServerName == "" &&
		!ev.Resumed && ev.LastAlert == "" && ev.NextProtocol == "" && !ev.Established &&
		len(ev.CertificateFileIDs) == 0 && len(ev.ClientCertificateFileIDs) == 0 &&
		ev.Subject == "" && ev.Issuer == "" && ev.ClientSubject == "" && ev.ClientIssuer == "" &&
		ev.ValidationStatus == "" && ev.JA3 == "" && ev.JA3S == "" && ev.JA4 == ""
}

func mergeTLS(dst *events.TLSEvent, server events.TLSEvent) {
	if server.Version != "" {
		dst.Version = server.Version
	}
	dst.Cipher, dst.Resumed, dst.LastAlert = server.Cipher, server.Resumed, server.LastAlert
	dst.NextProtocol, dst.Established = server.NextProtocol, server.Established
	dst.JA3S = server.JA3S
	if dst.ServerName == "" {
		dst.ServerName = server.ServerName
	}
	if dst.Curve == "" {
		dst.Curve = server.Curve
	}
	if dst.JA4 == "" {
		dst.JA4 = server.JA4
	}
}

func (s *Sink) enforceLimitLocked(ctx context.Context) error {
	for s.pendingCountLocked() > s.cfg.MaxPending {
		var oldest pending
		var httpUID string
		var tlsUID string
		var dnsTransaction dnsKey
		var haveDNS bool
		for uid, queue := range s.http {
			if len(queue) > 0 && (oldest.event == nil || queue[0].seen.Before(oldest.seen)) {
				oldest, httpUID, tlsUID = queue[0], uid, ""
			}
		}
		for uid, item := range s.tls {
			if oldest.event == nil || item.seen.Before(oldest.seen) {
				oldest, httpUID, tlsUID, haveDNS = item, "", uid, false
			}
		}
		for key, queue := range s.dns {
			if len(queue) > 0 && (oldest.event == nil || queue[0].seen.Before(oldest.seen)) {
				oldest, httpUID, tlsUID, dnsTransaction, haveDNS = queue[0], "", "", key, true
			}
		}
		if httpUID != "" {
			s.http[httpUID] = s.http[httpUID][1:]
			if len(s.http[httpUID]) == 0 {
				delete(s.http, httpUID)
			}
		} else if tlsUID != "" {
			delete(s.tls, tlsUID)
		} else if haveDNS {
			s.dns[dnsTransaction] = s.dns[dnsTransaction][1:]
			if len(s.dns[dnsTransaction]) == 0 {
				delete(s.dns, dnsTransaction)
			}
		}
		if err := s.emitPartialLocked(ctx, oldest.event); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sink) pendingCountLocked() int {
	n := len(s.tls)
	for _, queue := range s.dns {
		n += len(queue)
	}
	for _, queue := range s.http {
		n += len(queue)
	}
	return n
}

func (s *Sink) expireLocked(ctx context.Context, now time.Time) error {
	var result error
	for uid, queue := range s.http {
		for len(queue) > 0 && now.Sub(queue[0].seen) >= s.cfg.Timeout {
			result = errors.Join(result, s.emitPartialLocked(ctx, queue[0].event))
			queue = queue[1:]
		}
		if len(queue) == 0 {
			delete(s.http, uid)
		} else {
			s.http[uid] = queue
		}
	}
	for uid, item := range s.tls {
		if now.Sub(item.seen) >= s.cfg.Timeout {
			result = errors.Join(result, s.emitPartialLocked(ctx, item.event))
			delete(s.tls, uid)
		}
	}
	for key, queue := range s.dns {
		for len(queue) > 0 && now.Sub(queue[0].seen) >= s.cfg.Timeout {
			result = errors.Join(result, s.emitPartialLocked(ctx, queue[0].event))
			queue = queue[1:]
		}
		if len(queue) == 0 {
			delete(s.dns, key)
		} else {
			s.dns[key] = queue
		}
	}
	return result
}

func (s *Sink) emitPartialLocked(ctx context.Context, event events.Event) error {
	return s.next.HandleEvent(ctx, event)
}

func (s *Sink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result error
	for _, queue := range s.http {
		for _, item := range queue {
			result = errors.Join(result, s.next.HandleEvent(ctx, item.event))
		}
	}
	for _, item := range s.tls {
		result = errors.Join(result, s.next.HandleEvent(ctx, item.event))
	}
	for _, queue := range s.dns {
		for _, item := range queue {
			result = errors.Join(result, s.next.HandleEvent(ctx, item.event))
		}
	}
	s.http = make(map[string][]pending)
	s.tls = make(map[string]pending)
	s.dns = make(map[dnsKey][]pending)
	return errors.Join(result, s.next.Flush(ctx))
}
func (s *Sink) Close(ctx context.Context) error {
	s.once.Do(func() { close(s.done) })
	s.wg.Wait()
	// Close must be safe when called directly, not only through Dispatcher,
	// whose Stop currently invokes Flush first.
	return errors.Join(s.Flush(ctx), s.next.Close(ctx))
}
