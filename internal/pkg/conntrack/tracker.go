// Package conntrack provides bounded, direction-aware connection accounting.
package conntrack

import (
	"fmt"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/flowid"
)

const defaultShards = 64

// Config controls tracker scale and expiry behavior.
type Config struct {
	MaxFlows        int
	IdleTimeout     time.Duration
	HalfOpenTimeout time.Duration
	Shards          int
}

// Observation is the accounting information available for one IP packet.
type Observation struct {
	Envelope              events.Envelope
	IPBytes, PayloadBytes uint64
	Service               string
	TCP                   *TCPFlags
}

// TCPFlags is the TCP control information used by the state machine.
type TCPFlags struct{ SYN, ACK, FIN, RST bool }

// Stats is a lock-free snapshot apart from the current depth calculation.
type Stats struct {
	Depth, Capacity                  int
	Observations, Expired, Evictions uint64
}

type trackerKey struct {
	Flow   flowid.Key
	NodeID string
}
type direction uint8

const (
	origin direction = iota
	responder
)

type flow struct {
	key                                trackerKey
	env                                events.Envelope
	orig                               events.FlowTuple
	first, last                        time.Time
	origPkts, origIP, origPayload      uint64
	respPkts, respIP, respPayload      uint64
	service                            string
	partial                            bool
	seenOrig, seenResp                 bool
	synOrig, synResp, established      bool
	finOrig, finResp, rstOrig, rstResp bool
	history                            []byte
}

type shard struct {
	sync.Mutex
	flows map[trackerKey]*flow
}
type Tracker struct {
	cfg                              Config
	seed                             maphash.Seed
	shards                           []shard
	depth                            atomic.Int64
	observations, expired, evictions atomic.Uint64
}

func New(cfg Config) (*Tracker, error) {
	if cfg.MaxFlows <= 0 {
		return nil, fmt.Errorf("connection tracker flow cap must be positive")
	}
	if cfg.IdleTimeout <= 0 || cfg.HalfOpenTimeout <= 0 {
		return nil, fmt.Errorf("connection tracker timeouts must be positive")
	}
	if cfg.Shards <= 0 {
		cfg.Shards = defaultShards
	}
	t := &Tracker{cfg: cfg, seed: maphash.MakeSeed(), shards: make([]shard, cfg.Shards)}
	for i := range t.shards {
		t.shards[i].flows = make(map[trackerKey]*flow)
	}
	return t, nil
}

// Observe updates one flow and returns records evicted to preserve the hard cap.
func (t *Tracker) Observe(o Observation) ([]events.ConnEvent, error) {
	key, err := flowid.Normalize(o.Envelope.Flow)
	if err != nil {
		return nil, err
	}
	now := o.Envelope.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	t.observations.Add(1)
	tk := trackerKey{Flow: key, NodeID: o.Envelope.NodeID}
	s := t.shardFor(tk)
	s.Lock()
	f := s.flows[tk]
	if f == nil {
		f = newFlow(tk, o, now)
		s.flows[tk] = f
		t.depth.Add(1)
	} else {
		f.update(o, now)
	}
	s.Unlock()
	if int(t.depth.Load()) <= t.cfg.MaxFlows {
		return nil, nil
	}
	if ev, ok := t.evictOldest(); ok {
		t.evictions.Add(1)
		return []events.ConnEvent{ev}, nil
	}
	return nil, nil
}

func newFlow(key trackerKey, o Observation, now time.Time) *flow {
	if o.Envelope.Flow.Protocol == flowid.ProtocolTCP && o.TCP != nil && o.TCP.SYN && o.TCP.ACK {
		o.Envelope.Flow.SourceAddress, o.Envelope.Flow.DestinationAddress = o.Envelope.Flow.DestinationAddress, o.Envelope.Flow.SourceAddress
		o.Envelope.Flow.SourcePort, o.Envelope.Flow.DestinationPort = o.Envelope.Flow.DestinationPort, o.Envelope.Flow.SourcePort
	}
	f := &flow{key: key, env: o.Envelope, orig: o.Envelope.Flow, first: now, last: now, service: o.Service}
	// A TCP flow first seen without an initial SYN is explicitly partial.
	if o.Envelope.Flow.Protocol == flowid.ProtocolTCP && (o.TCP == nil || !o.TCP.SYN || o.TCP.ACK) {
		f.partial = true
	}
	if o.Envelope.CaptureScope == events.CaptureScopeFiltered {
		f.partial = true
	}
	f.update(o, now)
	return f
}

func (f *flow) update(o Observation, now time.Time) {
	d := origin
	if o.Envelope.Flow.SourceAddress != f.orig.SourceAddress || o.Envelope.Flow.SourcePort != f.orig.SourcePort {
		d = responder
	}
	if now.Before(f.first) {
		f.first = now
	}
	if now.After(f.last) {
		f.last = now
	}
	if o.Service != "" {
		f.service = o.Service
	}
	if d == origin {
		f.seenOrig = true
		f.origPkts++
		f.origIP += o.IPBytes
		f.origPayload += o.PayloadBytes
	} else {
		f.seenResp = true
		f.respPkts++
		f.respIP += o.IPBytes
		f.respPayload += o.PayloadBytes
	}
	if o.TCP == nil {
		return
	}
	flags := o.TCP
	if flags.SYN {
		if d == origin {
			f.synOrig = true
		} else {
			f.synResp = true
		}
		if flags.ACK && d == responder {
			f.addHistory(d, 'H', 'h')
		} else {
			f.addHistory(d, 'S', 's')
		}
	}
	if flags.SYN && flags.ACK && d == responder {
		f.established = true
	}
	if flags.ACK && !flags.SYN {
		f.addHistory(d, 'A', 'a')
	}
	if o.PayloadBytes > 0 {
		f.addHistory(d, 'D', 'd')
	}
	if flags.FIN {
		if d == origin {
			f.finOrig = true
		} else {
			f.finResp = true
		}
		f.addHistory(d, 'F', 'f')
	}
	if flags.RST {
		if d == origin {
			f.rstOrig = true
		} else {
			f.rstResp = true
		}
		f.addHistory(d, 'R', 'r')
	}
}

func (f *flow) addHistory(d direction, upper, lower byte) {
	b := upper
	if d == responder {
		b = lower
	}
	if len(f.history) == 0 || f.history[len(f.history)-1] != b {
		f.history = append(f.history, b)
	}
}

func (t *Tracker) Expire(now time.Time) []events.ConnEvent {
	var out []events.ConnEvent
	for i := range t.shards {
		s := &t.shards[i]
		s.Lock()
		for k, f := range s.flows {
			timeout := t.cfg.IdleTimeout
			if f.orig.Protocol == flowid.ProtocolTCP && !f.established {
				timeout = t.cfg.HalfOpenTimeout
			}
			if !f.last.Add(timeout).After(now) {
				out = append(out, f.event())
				delete(s.flows, k)
				t.depth.Add(-1)
				t.expired.Add(1)
			}
		}
		s.Unlock()
	}
	return out
}

// Close emits every remaining flow. The tracker is empty when it returns.
func (t *Tracker) Close() []events.ConnEvent {
	var out []events.ConnEvent
	for i := range t.shards {
		s := &t.shards[i]
		s.Lock()
		for k, f := range s.flows {
			out = append(out, f.event())
			delete(s.flows, k)
			t.depth.Add(-1)
		}
		s.Unlock()
	}
	return out
}

func (f *flow) event() events.ConnEvent {
	env := f.env
	env.Timestamp = f.first
	env.Flow = f.orig
	env.Partial = env.Partial || f.partial || !f.seenResp
	e := events.NewConnEvent(env)
	e.Service = f.service
	e.Duration = f.last.Sub(f.first)
	e.OriginBytes = f.origPayload
	e.ResponseBytes = f.respPayload
	e.OriginPackets = f.origPkts
	e.OriginIPBytes = f.origIP
	e.ResponsePackets = f.respPkts
	e.ResponseIPBytes = f.respIP
	e.State = f.state()
	if !env.Partial {
		e.History = string(f.history)
	}
	return e
}

func (f *flow) state() string {
	if f.orig.Protocol != flowid.ProtocolTCP {
		if f.seenResp {
			return "SF"
		}
		return "S0"
	}
	if f.synOrig && f.rstResp && !f.established {
		return "REJ"
	}
	if f.synOrig && !f.synResp {
		if f.finOrig {
			return "SH"
		}
		return "S0"
	}
	if f.established {
		if f.rstOrig {
			return "RSTO"
		}
		if f.rstResp {
			return "RSTR"
		}
		if f.finOrig && f.finResp {
			return "SF"
		}
		return "S1"
	}
	if f.synResp && f.finResp && !f.seenOrig {
		return "SHR"
	}
	return "OTH"
}

func (t *Tracker) shardFor(k trackerKey) *shard {
	var h maphash.Hash
	h.SetSeed(t.seed)
	h.WriteString(k.NodeID)
	h.WriteByte(k.Flow.Protocol)
	h.Write(k.Flow.Address1.AsSlice())
	h.Write(k.Flow.Address2.AsSlice())
	var p [4]byte
	p[0] = byte(k.Flow.Port1 >> 8)
	p[1] = byte(k.Flow.Port1)
	p[2] = byte(k.Flow.Port2 >> 8)
	p[3] = byte(k.Flow.Port2)
	h.Write(p[:])
	return &t.shards[h.Sum64()%uint64(len(t.shards))]
}

func (t *Tracker) evictOldest() (events.ConnEvent, bool) {
	var candidate trackerKey
	var candidateTime time.Time
	found := false
	var cs *shard
	for i := range t.shards {
		s := &t.shards[i]
		s.Lock()
		for _, f := range s.flows {
			if !found || f.last.Before(candidateTime) {
				candidate, candidateTime, found = f.key, f.last, true
				cs = s
			}
		}
		s.Unlock()
	}
	if !found {
		return events.ConnEvent{}, false
	}
	cs.Lock()
	f, ok := cs.flows[candidate]
	if ok {
		delete(cs.flows, candidate)
		t.depth.Add(-1)
	}
	cs.Unlock()
	if !ok {
		return t.evictOldest()
	}
	return f.event(), true
}

func (t *Tracker) Stats() Stats {
	return Stats{Depth: int(t.depth.Load()), Capacity: t.cfg.MaxFlows, Observations: t.observations.Load(), Expired: t.expired.Load(), Evictions: t.evictions.Load()}
}
