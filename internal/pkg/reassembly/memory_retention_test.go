package reassembly

import (
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type retentionFactory struct {
	mu      sync.Mutex
	streams []*retentionStream
	onNew   func()
}

type retentionStream struct {
	mu          sync.Mutex
	completions int
}

func (f *retentionFactory) New(gopacket.Flow, gopacket.Flow, *layers.TCP, AssemblerContext) Stream {
	s := &retentionStream{}
	f.mu.Lock()
	f.streams = append(f.streams, s)
	f.mu.Unlock()
	if f.onNew != nil {
		f.onNew()
	}
	return s
}

func (*retentionStream) Accept(*layers.TCP, gopacket.CaptureInfo, TCPFlowDirection, Sequence, *bool, AssemblerContext) bool {
	return true
}

func (*retentionStream) ReassembledSG(ScatterGather, AssemblerContext) {}

func (s *retentionStream) ReassemblyComplete(AssemblerContext) bool {
	s.mu.Lock()
	s.completions++
	s.mu.Unlock()
	return true
}

func (s *retentionStream) completed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completions
}

func assertRetiredStreamsReleased(t *testing.T, p *StreamPool) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns) != 0 {
		t.Fatalf("%d connections still active", len(p.conns))
	}
	for _, c := range p.free {
		if c.c2s.stream != nil || c.s2c.stream != nil {
			t.Fatalf("free connection %p retains streams", c)
		}
	}
}

func retentionPacket(src, dst layers.TCPPort, syn, end bool) layers.TCP {
	tcp := layers.TCP{SrcPort: src, DstPort: dst, SYN: syn, FIN: end, Seq: 1}
	if end {
		tcp.Seq = 2
	}
	tcp.SetInternalPortsForTesting()
	return tcp
}

func TestStreamPoolReleasesCompletedStreams(t *testing.T) {
	for _, closeBy := range []string{"fin", "rst", "flush"} {
		t.Run(closeBy, func(t *testing.T) {
			f := &retentionFactory{}
			p := NewStreamPool(f)
			a := NewAssembler(p)
			syn := retentionPacket(50123, 5060, true, false)
			a.Assemble(netFlow, &syn)
			p.mu.RLock()
			original := p.conns[key{netFlow, syn.TransportFlow()}]
			p.mu.RUnlock()
			if original == nil {
				t.Fatal("missing active connection")
			}
			switch closeBy {
			case "fin", "rst":
				reverseSyn := retentionPacket(5060, 50123, true, false)
				a.Assemble(netFlow.Reverse(), &reverseSyn)
				end := retentionPacket(50123, 5060, false, true)
				reverse := retentionPacket(5060, 50123, false, true)
				if closeBy == "rst" {
					end.FIN, reverse.FIN = false, false
					end.RST, reverse.RST = true, true
				}
				a.Assemble(netFlow, &end)
				a.Assemble(netFlow.Reverse(), &reverse)
			case "flush":
				a.FlushCloseOlderThan(time.Now().Add(time.Hour))
			}
			assertRetiredStreamsReleased(t, p)
			if got := f.streams[0].completed(); got != 1 {
				t.Fatalf("original stream completed %d times, want 1", got)
			}

			// A new session with the same key should reuse the slab without
			// reusing the completed Stream in either direction.
			a.Assemble(netFlow, &syn)
			p.mu.RLock()
			reused := p.conns[key{netFlow, syn.TransportFlow()}]
			p.mu.RUnlock()
			if reused != original {
				t.Fatalf("connection slab %p was not reused; got %p", original, reused)
			}
			if len(f.streams) != 2 || reused.c2s.stream != f.streams[1] || reused.s2c.stream != f.streams[1] {
				t.Fatal("reused connection does not have the fresh stream in both directions")
			}
			a.FlushAll()
			assertRetiredStreamsReleased(t, p)
			if got := f.streams[1].completed(); got != 1 {
				t.Fatalf("reused stream completed %d times, want 1", got)
			}
		})
	}
}

func TestStreamPoolConcurrentAssembleAndFlush(t *testing.T) {
	f := &retentionFactory{}
	p := NewStreamPool(f)
	const workers = 8
	const sessions = 32
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			a := NewAssembler(p)
			for session := range sessions {
				port := layers.TCPPort(10000 + worker*sessions + session)
				syn := retentionPacket(port, 5060, true, false)
				a.Assemble(netFlow, &syn)
				if session%2 == 0 {
					a.FlushAll()
				}
			}
		}(worker)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		a := NewAssembler(p)
		for range workers * sessions {
			a.FlushAll()
		}
	}()
	wg.Wait()
	NewAssembler(p).FlushAll()
	assertRetiredStreamsReleased(t, p)
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, s := range f.streams {
		if got := s.completed(); got != 1 {
			t.Errorf("stream %d completed %d times, want 1", i, got)
		}
	}
}

func TestStreamPoolWaitsForOutstandingAssemblerPointer(t *testing.T) {
	f := &retentionFactory{}
	p := NewStreamPool(f)
	tcp := retentionPacket(50234, 5060, true, false)
	k := key{netFlow, tcp.TransportFlow()}
	conn, _, _ := p.getConnection(k, false, time.Now(), &tcp, nil)
	if conn == nil {
		t.Fatal("missing connection")
	}
	if !conn.c2s.stream.ReassemblyComplete(nil) {
		t.Fatal("test stream refused completion")
	}
	p.remove(conn)
	p.mu.RLock()
	retired := conn.retired
	retained := conn.c2s.stream != nil && conn.s2c.stream != nil
	freeCount := len(p.free)
	p.mu.RUnlock()
	if !retired || !retained || freeCount != initialAllocSize-1 {
		t.Fatal("retired connection was recycled while an assembler still held its pointer")
	}
	p.release(conn)
	assertRetiredStreamsReleased(t, p)
	p.mu.RLock()
	freeCount = len(p.free)
	p.mu.RUnlock()
	if freeCount != initialAllocSize {
		t.Fatalf("free pool has %d entries after release, want %d", freeCount, initialAllocSize)
	}
}

func TestStreamPoolConcurrentSameKeyCreation(t *testing.T) {
	entered := make(chan struct{}, 1)
	unblock := make(chan struct{})
	f := &retentionFactory{onNew: func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-unblock
	}}
	p := NewStreamPool(f)
	const workers = 24
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a := NewAssembler(p)
		syn := retentionPacket(50345, 5060, true, false)
		a.Assemble(netFlow, &syn)
	}()
	<-entered
	ready := make(chan struct{}, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			a := NewAssembler(p)
			syn := retentionPacket(50345, 5060, true, false)
			a.Assemble(netFlow, &syn)
		}()
	}
	for range workers {
		<-ready
	}
	close(unblock)
	wg.Wait()
	NewAssembler(p).FlushAll()
	assertRetiredStreamsReleased(t, p)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.streams) != 1 {
		t.Fatalf("factory created %d streams for one live flow, want 1", len(f.streams))
	}
	for i, s := range f.streams {
		if got := s.completed(); got != 1 {
			t.Errorf("stream %d completed %d times, want 1", i, got)
		}
	}
}

func TestStreamPoolEndLookupWaitsForReverseCreation(t *testing.T) {
	entered := make(chan struct{}, 1)
	unblock := make(chan struct{})
	f := &retentionFactory{onNew: func() {
		entered <- struct{}{}
		<-unblock
	}}
	p := NewStreamPool(f)
	tcp := retentionPacket(50456, 5060, true, false)
	k := key{netFlow, tcp.TransportFlow()}
	created := make(chan *connection, 1)
	go func() {
		conn, _, _ := p.getConnection(k, false, time.Now(), &tcp, nil)
		created <- conn
	}()
	<-entered
	reverse := retentionPacket(5060, 50456, false, true)
	lookedUp := make(chan *connection, 1)
	go func() {
		conn, _, _ := p.getConnection(k.Reverse(), true, time.Now(), &reverse, nil)
		lookedUp <- conn
	}()
	close(unblock)
	first := <-created
	second := <-lookedUp
	if first == nil || second != first {
		t.Fatal("end-only reverse lookup missed an in-flight connection")
	}
	p.release(first)
	p.release(second)
	NewAssembler(p).FlushAll()
	assertRetiredStreamsReleased(t, p)
}
