// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package reassembly

import (
	"flag"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"
)

var memLog = flag.Bool("assembly_memuse_log", defaultDebug, "If true, the github.com/google/gopacket/reassembly library will log information regarding its memory use every once in a while.")

/*
 * pageCache
 */
// pageCache is a concurrency-unsafe store of page objects we use to avoid
// memory allocation as much as we can.
type pageCache struct {
	free         []*page
	pcSize       int
	size, used   int
	pageRequests int64
	ops          int
	nextShrink   int
}

const initialAllocSize = 1024

func newPageCache() *pageCache {
	pc := &pageCache{
		free:   make([]*page, 0, initialAllocSize),
		pcSize: initialAllocSize,
	}
	pc.grow()
	return pc
}

// grow exponentially increases the size of our page cache as much as necessary.
func (c *pageCache) grow() {
	pages := make([]page, c.pcSize)
	c.size += c.pcSize
	for i := range pages {
		c.free = append(c.free, &pages[i])
	}
	if *memLog {
		log.Println("PageCache: created", c.pcSize, "new pages, size:", c.size, "cap:", cap(c.free), "len:", len(c.free))
	}
	// control next shrink attempt
	c.nextShrink = c.pcSize
	c.ops = 0
	// prepare for next alloc
	c.pcSize *= 2
}

// Remove references to unused pages to let GC collect them
// Note: memory used by c.free itself it not collected.
func (c *pageCache) tryShrink() {
	var min = c.pcSize / 2
	if min < initialAllocSize {
		min = initialAllocSize
	}
	if len(c.free) <= min {
		return
	}
	for i := range c.free[min:] {
		c.free[min+i] = nil
	}
	c.size -= len(c.free) - min
	c.free = c.free[:min]
	c.pcSize = min
}

// next returns a clean, ready-to-use page object.
func (c *pageCache) next(ts time.Time) (p *page) {
	if *memLog {
		c.pageRequests++
		if c.pageRequests&0xFFFF == 0 {
			log.Println("PageCache:", c.pageRequests, "requested,", c.used, "used,", len(c.free), "free")
		}
	}
	if len(c.free) == 0 {
		c.grow()
	}
	i := len(c.free) - 1
	p, c.free = c.free[i], c.free[:i]
	p.seen = ts
	p.bytes = p.buf[:0]
	c.used++
	if *memLog {
		log.Printf("allocator returns %s\n", p)
	}
	c.ops++
	if c.ops > c.nextShrink {
		c.ops = 0
		c.tryShrink()
	}

	return p
}

// replace replaces a page into the pageCache.
func (c *pageCache) replace(p *page) {
	c.used--
	if *memLog {
		log.Printf("replacing %s\n", p)
	}
	p.prev = nil
	p.next = nil
	p.ac = nil
	p.continuationContext = nil
	c.free = append(c.free, p)
}

/*
 * StreamPool
 */

// StreamPool stores all streams created by Assemblers, allowing multiple
// assemblers to work together on stream processing while enforcing the fact
// that a single stream receives its data serially.  It is safe
// for concurrency, usable by multiple Assemblers at once.
//
// StreamPool handles the creation and storage of Stream objects used by one or
// more Assembler objects.  When a new TCP stream is found by an Assembler, it
// creates an associated Stream by calling its StreamFactory's New method.
// Thereafter (until the stream is closed), that Stream object will receive
// assembled TCP data via Assembler's calls to the stream's Reassembled
// function.
//
// Like the Assembler, StreamPool attempts to minimize allocation.  Unlike the
// Assembler, though, it does have to do some locking to make sure that the
// connection objects it stores are accessible to multiple Assemblers.
type StreamPool struct {
	conns              map[key]*connection
	creating           map[key]chan struct{}
	mu                 sync.RWMutex
	factory            StreamFactory
	free               []*connection
	all                [][]connection
	nextAlloc          int
	newConnectionCount int64
	orphanControls     atomic.Uint64
}

func (p *StreamPool) grow() {
	conns := make([]connection, p.nextAlloc)
	p.all = append(p.all, conns)
	for i := range conns {
		p.free = append(p.free, &conns[i])
	}
	if *memLog {
		log.Println("StreamPool: created", p.nextAlloc, "new connections")
	}
	p.nextAlloc *= 2
}

// Dump logs all connections
func (p *StreamPool) Dump() {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.Printf("Remaining %d connections: ", len(p.conns))
	for _, conn := range p.conns {
		log.Printf("%v %s", conn.key, conn)
	}
}

func (p *StreamPool) remove(conn *connection) {
	p.mu.Lock()
	if p.conns[conn.key] == conn {
		delete(p.conns, conn.key)
		conn.retired = true
		if conn.pins == 0 {
			p.recycle(conn)
		}
	}
	p.mu.Unlock()
}

// recycle is called under p.mu after the final user of a completed connection
// has released its pointer. The slab remains available for the next stream.
func (p *StreamPool) recycle(conn *connection) {
	conn.c2s.stream = nil
	conn.s2c.stream = nil
	p.free = append(p.free, conn)
}

func (p *StreamPool) release(conn *connection) {
	p.mu.Lock()
	conn.pins--
	if conn.retired && conn.pins == 0 {
		p.recycle(conn)
	}
	p.mu.Unlock()
}

func (p *StreamPool) isRetired(conn *connection) bool {
	p.mu.RLock()
	retired := conn.retired
	p.mu.RUnlock()
	return retired
}

// NewStreamPool creates a new connection pool.  Streams will
// be created as necessary using the passed-in StreamFactory.
func NewStreamPool(factory StreamFactory) *StreamPool {
	return &StreamPool{
		conns:     make(map[key]*connection, initialAllocSize),
		creating:  make(map[key]chan struct{}),
		free:      make([]*connection, 0, initialAllocSize),
		factory:   factory,
		nextAlloc: initialAllocSize,
	}
}

func (p *StreamPool) connections() []*connection {
	p.mu.Lock()
	conns := make([]*connection, 0, len(p.conns))
	for _, conn := range p.conns {
		conn.pins++
		conns = append(conns, conn)
	}
	p.mu.Unlock()
	return conns
}

func (p *StreamPool) newConnection(k key, s Stream, ts time.Time) (c *connection, h *halfconnection, r *halfconnection) {
	if *memLog {
		p.newConnectionCount++
		if p.newConnectionCount&0x7FFF == 0 {
			log.Println("StreamPool:", p.newConnectionCount, "requests,", len(p.conns), "used,", len(p.free), "free")
		}
	}
	if len(p.free) == 0 {
		p.grow()
	}
	index := len(p.free) - 1
	c, p.free = p.free[index], p.free[:index]
	c.reset(k, s, ts)
	c.retired = false
	c.pins = 1
	return c, &c.c2s, &c.s2c
}

func (p *StreamPool) getHalf(k key) (*connection, *halfconnection, *halfconnection) {
	conn := p.conns[k]
	if conn != nil {
		return conn, &conn.c2s, &conn.s2c
	}
	rk := k.Reverse()
	conn = p.conns[rk]
	if conn != nil {
		return conn, &conn.s2c, &conn.c2s
	}
	return nil, nil, nil
}

// OrphanControls returns control-only packets rejected without creating a stream.
func (p *StreamPool) OrphanControls() uint64 { return p.orphanControls.Load() }

// getConnection returns a connection.  If end is true and a connection
// does not already exist, returns nil.  This allows us to check for a
// connection without actually creating one if it doesn't already exist.
func (p *StreamPool) getConnection(k key, end bool, ts time.Time, tcp *layers.TCP, ac AssemblerContext) (*connection, *halfconnection, *halfconnection) {
	for {
		p.mu.Lock()
		conn, half, rev := p.getHalf(k)
		if conn != nil {
			conn.pins++
			p.mu.Unlock()
			return conn, half, rev
		}
		if pending := p.creating[k]; pending != nil {
			p.mu.Unlock()
			<-pending
			continue
		}
		if pending := p.creating[k.Reverse()]; pending != nil {
			p.mu.Unlock()
			<-pending
			continue
		}
		if end {
			p.orphanControls.Add(1)
			p.mu.Unlock()
			return nil, nil, nil
		}
		pending := make(chan struct{})
		p.creating[k] = pending
		p.mu.Unlock()

		// A single factory callback creates each key. A losing callback cannot
		// safely be completed: completion may have side effects on the live flow.
		// Other keys can still be created while this factory call runs.
		created := false
		func() {
			defer func() {
				if !created {
					p.mu.Lock()
					delete(p.creating, k)
					close(pending)
					p.mu.Unlock()
				}
			}()
			s := p.factory.New(k[0], k[1], tcp, ac)
			p.mu.Lock()
			conn, half, rev = p.newConnection(k, s, ts)
			p.conns[k] = conn
			delete(p.creating, k)
			close(pending)
			p.mu.Unlock()
			created = true
		}()
		return conn, half, rev
	}
}
