// Package flowid provides direction-independent flow keys and stable identities.
package flowid

import (
	"container/list"
	"crypto/rand"
	"crypto/sha1" // Community ID v1 requires SHA-1 for compatibility.
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
)

const (
	ProtocolICMP   = 1
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolICMPv6 = 58
)

var ErrInvalidTuple = errors.New("invalid flow tuple")

// Key is a comparable, direction-normalized flow key.
type Key struct {
	Protocol uint8
	Address1 netip.Addr
	Address2 netip.Addr
	Port1    uint16
	Port2    uint16
}

// Normalize returns a canonical key. ICMP request/reply types are treated as
// port equivalents as required by Community ID v1.
func Normalize(flow events.FlowTuple) (Key, error) {
	a, b := flow.SourceAddress.Unmap(), flow.DestinationAddress.Unmap()
	if !a.IsValid() || !b.IsValid() || a.BitLen() != b.BitLen() {
		return Key{}, fmt.Errorf("%w: addresses must be valid and from the same family", ErrInvalidTuple)
	}
	p1, p2 := flow.SourcePort, flow.DestinationPort
	oneWay := false
	switch flow.Protocol {
	case ProtocolICMP:
		if p1 > 255 || p2 > 255 {
			return Key{}, fmt.Errorf("%w: ICMP type and code must fit in one byte", ErrInvalidTuple)
		}
		if counterpart, ok := icmp4Counterpart(uint8(p1)); ok {
			p2 = uint16(counterpart)
		} else {
			oneWay = true
		}
	case ProtocolICMPv6:
		if p1 > 255 || p2 > 255 {
			return Key{}, fmt.Errorf("%w: ICMPv6 type and code must fit in one byte", ErrInvalidTuple)
		}
		if counterpart, ok := icmp6Counterpart(uint8(p1)); ok {
			p2 = uint16(counterpart)
		} else {
			oneWay = true
		}
	}
	if !oneWay && endpointLess(b, p2, a, p1) {
		a, b, p1, p2 = b, a, p2, p1
	}
	return Key{Protocol: flow.Protocol, Address1: a, Address2: b, Port1: p1, Port2: p2}, nil
}

func endpointLess(a netip.Addr, portA uint16, b netip.Addr, portB uint16) bool {
	if cmp := a.Compare(b); cmp != 0 {
		return cmp < 0
	}
	return portA < portB
}

func icmp4Counterpart(t uint8) (uint8, bool) {
	switch t {
	case 0:
		return 8, true
	case 8:
		return 0, true
	case 9:
		return 10, true
	case 10:
		return 9, true
	case 13:
		return 14, true
	case 14:
		return 13, true
	case 15:
		return 16, true
	case 16:
		return 15, true
	case 17:
		return 18, true
	case 18:
		return 17, true
	default:
		return 0, false
	}
}

func icmp6Counterpart(t uint8) (uint8, bool) {
	switch t {
	case 128:
		return 129, true
	case 129:
		return 128, true
	case 130:
		return 131, true
	case 131:
		return 130, true
	case 133:
		return 134, true
	case 134:
		return 133, true
	case 135:
		return 136, true
	case 136:
		return 135, true
	case 139:
		return 140, true
	case 140:
		return 139, true
	case 144:
		return 145, true
	case 145:
		return 144, true
	default:
		return 0, false
	}
}

// CommunityID returns a base64-encoded Community ID v1 for flow and seed.
func CommunityID(flow events.FlowTuple, seed uint16) (string, error) {
	key, err := Normalize(flow)
	if err != nil {
		return "", err
	}
	return calculateCommunityID(key, seed), nil
}

func calculateCommunityID(key Key, seed uint16) string {
	h := sha1.New()
	var word [2]byte
	binary.BigEndian.PutUint16(word[:], seed)
	_, _ = h.Write(word[:])
	writeAddress(h, key.Address1)
	writeAddress(h, key.Address2)
	_, _ = h.Write([]byte{key.Protocol, 0})
	if protocolHasPorts(key.Protocol) {
		binary.BigEndian.PutUint16(word[:], key.Port1)
		_, _ = h.Write(word[:])
		binary.BigEndian.PutUint16(word[:], key.Port2)
		_, _ = h.Write(word[:])
	}
	return "1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type byteWriter interface{ Write([]byte) (int, error) }

func writeAddress(w byteWriter, addr netip.Addr) {
	if addr.Is4() {
		v := addr.As4()
		_, _ = w.Write(v[:])
		return
	}
	v := addr.As16()
	_, _ = w.Write(v[:])
}

func protocolHasPorts(protocol uint8) bool {
	return protocol == ProtocolTCP || protocol == ProtocolUDP || protocol == 132 || protocol == ProtocolICMP || protocol == ProtocolICMPv6
}

// Identity is the stable identity assigned to a cached flow.
type Identity struct {
	UID         string
	CommunityID string
}

type Config struct {
	MaxEntries  int
	IdleTimeout time.Duration
	Seed        uint16
}

type Stats struct {
	Size      int
	Capacity  int
	Lookups   uint64
	Hits      uint64
	Misses    uint64
	Evictions uint64
	Expired   uint64
}

type entry struct {
	key      Key
	identity Identity
	lastSeen time.Time
}

// Cache maintains bounded Zeek UIDs and Community IDs for observed flows.
type Cache struct {
	cfg                                       Config
	mu                                        sync.Mutex
	entries                                   map[Key]*list.Element
	lru                                       list.List
	lookups, hits, misses, evictions, expired atomic.Uint64
}

func NewCache(cfg Config) (*Cache, error) {
	if cfg.MaxEntries <= 0 {
		return nil, fmt.Errorf("flow identity cache size must be positive")
	}
	if cfg.IdleTimeout <= 0 {
		return nil, fmt.Errorf("flow identity idle timeout must be positive")
	}
	return &Cache{cfg: cfg, entries: make(map[Key]*list.Element, cfg.MaxEntries)}, nil
}

// Lookup returns the identity for flow, creating one on a cache miss.
func (c *Cache) Lookup(flow events.FlowTuple, now time.Time) (Identity, error) {
	key, err := Normalize(flow)
	if err != nil {
		return Identity{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	c.lookups.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	if elem, ok := c.entries[key]; ok {
		item := elem.Value.(*entry)
		item.lastSeen = now
		c.lru.MoveToFront(elem)
		c.hits.Add(1)
		return item.identity, nil
	}
	c.misses.Add(1)
	communityID := calculateCommunityID(key, c.cfg.Seed)
	uid, err := newUID()
	if err != nil {
		return Identity{}, fmt.Errorf("generate flow UID: %w", err)
	}
	identity := Identity{UID: uid, CommunityID: communityID}
	elem := c.lru.PushFront(&entry{key: key, identity: identity, lastSeen: now})
	c.entries[key] = elem
	if c.lru.Len() > c.cfg.MaxEntries {
		c.removeLocked(c.lru.Back())
		c.evictions.Add(1)
	}
	return identity, nil
}

// Enrich attaches stable flow identity to an event envelope.
func (c *Cache) Enrich(env events.Envelope) (events.Envelope, error) {
	identity, err := c.Lookup(env.Flow, env.Timestamp)
	if err != nil {
		return env, err
	}
	env.UID, env.CommunityID = identity.UID, identity.CommunityID
	return env, nil
}

func (c *Cache) expireLocked(now time.Time) {
	cutoff := now.Add(-c.cfg.IdleTimeout)
	for elem := c.lru.Back(); elem != nil; elem = c.lru.Back() {
		if elem.Value.(*entry).lastSeen.After(cutoff) {
			return
		}
		c.removeLocked(elem)
		c.expired.Add(1)
	}
}

func (c *Cache) removeLocked(elem *list.Element) {
	delete(c.entries, elem.Value.(*entry).key)
	c.lru.Remove(elem)
}

func (c *Cache) Stats() Stats {
	c.mu.Lock()
	size := c.lru.Len()
	c.mu.Unlock()
	return Stats{Size: size, Capacity: c.cfg.MaxEntries, Lookups: c.lookups.Load(), Hits: c.hits.Load(), Misses: c.misses.Load(), Evictions: c.evictions.Load(), Expired: c.expired.Load()}
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func newUID() (string, error) {
	uid := [18]byte{'C'}
	// Discard the top eight byte values to avoid modulo bias.
	for i := 1; i < len(uid); {
		var random [17]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", err
		}
		for _, value := range random {
			if value >= 248 {
				continue
			}
			uid[i] = base62[int(value)%len(base62)]
			i++
			if i == len(uid) {
				break
			}
		}
	}
	return string(uid[:]), nil
}
