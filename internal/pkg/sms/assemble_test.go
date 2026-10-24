package sms

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func segment(part uint8, text string) *Message {
	return &Message{Text: text, Status: StatusDecoded, Direction: DirectionMO, Encoding: EncodingGSM7, To: "+12345", Concat: &Concatenation{Reference: 42, ReferenceBits: 8, Total: 2, Part: part}}
}

func TestAssemblyOrderOwnershipAndDuplicates(t *testing.T) {
	a := NewAssembler(Config{})
	now := time.Unix(100, 0)
	m := segment(2, "world")
	out := a.Add("capture/subscriber", m, now)
	if out.Assembly.Status != AssemblyPending || out.Assembly.Text != "world" || len(out.Assembly.Missing) != 1 || out.Assembly.Missing[0] != 1 {
		t.Fatalf("pending %#v", out.Assembly)
	}
	m.Text = "changed"
	out.Assembly.Received[0] = 99
	full := a.Add("capture/subscriber", segment(1, "hello "), now.Add(time.Second))
	if full.Text != "hello " || full.Assembly.Text != "hello world" || full.Assembly.Status != AssemblyComplete {
		t.Fatalf("complete %#v", full)
	}
	before := a.Stats()
	duplicate := a.Add("capture/subscriber", segment(2, "world"), now.Add(2*time.Second))
	if duplicate.Assembly.ID != full.Assembly.ID || a.Stats() != before {
		t.Fatal("duplicate modified retention")
	}
	conflict := a.Add("capture/subscriber", segment(2, "different"), now.Add(3*time.Second))
	if conflict.Assembly.Status != AssemblyConflict || conflict.Assembly.Text != "hello world" {
		t.Fatalf("conflict %#v", conflict.Assembly)
	}
	if a.Add("capture/subscriber", segment(2, "world"), now).Assembly.Status != AssemblyConflict {
		t.Fatal("conflict forgotten")
	}
}

func TestAssemblyScopesAndCompatibility(t *testing.T) {
	now := time.Unix(100, 0)
	a := NewAssembler(Config{})
	a.Add("source1", segment(1, "one"), now)
	for _, change := range []func(*Message){func(m *Message) { m.To = "+54321" }, func(m *Message) { m.Direction = DirectionMT }, func(m *Message) { m.Concat.ReferenceBits = 16 }} {
		m := segment(2, "two")
		change(m)
		if a.Add("source1", m, now).Assembly.Status != AssemblyPending {
			t.Fatal("incompatible source grouping")
		}
	}
	if a.Add("source2", segment(2, "two"), now).Assembly.Status != AssemblyPending {
		t.Fatal("source crossed")
	}
	if a.Add("source1", segment(2, "two"), now).Assembly.Text != "onetwo" {
		t.Fatal("compatible grouping")
	}
	for _, scope := range []string{"", "ambiguous"} {
		m := segment(1, "one")
		if scope != "" {
			m.To = ""
		}
		a.Add(scope, m, now)
		m.Concat.Part = 2
		if a.Add(scope, m, now).Assembly.Status == AssemblyComplete {
			t.Fatal("ambiguous merge")
		}
	}
}

func TestAssemblyIncompatibleHeadersConflict(t *testing.T) {
	for _, change := range []func(*Message){func(m *Message) { m.Encoding = EncodingUCS2; m.DCS = 8 }, func(m *Message) { m.Concat.Total = 3 }, func(m *Message) { m.Header = []byte{5, 2, 1, 2} }} {
		a := NewAssembler(Config{})
		now := time.Unix(100, 0)
		a.Add("scope", segment(1, "one"), now)
		m := segment(2, "two")
		change(m)
		if a.Add("scope", m, now).Assembly.Status != AssemblyConflict {
			t.Fatal("incompatible content was not conflicting")
		}
		if a.Add("scope", segment(2, "two"), now).Assembly.Status != AssemblyConflict {
			t.Fatal("conflict became complete")
		}
	}
}

func TestAssemblyExpiryLimitsAndLifecycle(t *testing.T) {
	now := time.Unix(100, 0)
	a := NewAssembler(Config{Lifetime: time.Second})
	first := a.Add("scope", segment(1, "old"), now)
	a.Add("scope", segment(1, "old"), now.Add(900*time.Millisecond))
	expired := a.Expire(now.Add(time.Second))
	if len(expired) != 1 || expired[0].Assembly.Status != AssemblyExpired || a.Stats().Assemblies != 0 || a.Stats().Bytes != 0 {
		t.Fatalf("expiry %#v %#v", expired, a.Stats())
	}
	second := a.Add("scope", segment(1, "new"), now.Add(time.Second))
	if second.Assembly.ID == first.Assembly.ID {
		t.Fatal("reference reuse has stale identity")
	}
	a.Reset()
	if a.Stats() != (Stats{}) {
		t.Fatal("reset retained content")
	}
	a.Close()
	if a.Add("scope", segment(1, "one"), now).Assembly.Status != AssemblyResourceLimited || a.Stats().Assemblies != 0 {
		t.Fatal("closed retention")
	}
	for _, config := range []Config{{MaxAssemblies: 1}, {MaxBytes: 1100}, {MaxSegments: 1}} {
		a = NewAssembler(config)
		a.Add("scope", segment(1, "one"), now)
		result := a.Add("different", segment(2, strings.Repeat("x", 1000)), now)
		if result.Assembly.Status != AssemblyResourceLimited {
			t.Fatalf("limits %#v %#v", config, result.Assembly)
		}
	}
	// Completed groups consume the same count budget as pending groups.
	a = NewAssembler(Config{MaxAssemblies: 1})
	a.Add("scope", segment(1, "one"), now)
	a.Add("scope", segment(2, "two"), now)
	if a.Add("different", segment(1, "three"), now).Assembly.Status != AssemblyResourceLimited {
		t.Fatal("unbounded completed results")
	}
}

func TestAssemblyConcurrentAndClone(t *testing.T) {
	a := NewAssembler(Config{})
	defer a.Close()
	now := time.Unix(100, 0)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Add("scope", segment(1, "one"), now)
			a.Add("scope", segment(2, "two"), now)
			a.Stats()
		}()
	}
	wg.Wait()
	if a.Stats().Assemblies != 1 || a.Stats().Segments != 2 {
		t.Fatal(a.Stats())
	}
	m := segment(1, "one")
	m.Header = []byte{1}
	m.Assembly.Missing = []uint8{2}
	copy := Clone(m)
	copy.Concat.Part = 2
	copy.Header[0] = 2
	copy.Assembly.Missing[0] = 3
	if m.Concat.Part != 1 || m.Header[0] != 1 || m.Assembly.Missing[0] != 2 {
		t.Fatal("shallow clone")
	}
}

func TestAssemblyRealDecodedSegments(t *testing.T) {
	for _, wide := range []bool{false, true} {
		a := NewAssembler(Config{})
		now := time.Unix(100, 0)
		for part := byte(2); part > 0; part-- {
			header := []byte{5, 0, 3, 4, 2, part}
			if wide {
				header = []byte{6, 8, 4, 0, 4, 2, part}
			}
			text := []byte("hello ")
			if part == 2 {
				text = []byte("world")
			}
			ud, n := pack(header, text)
			m, e := Decode(rp(submit(ud, n, 0, 0x41), false))
			if e != nil {
				t.Fatal(e)
			}
			out := a.Add("subscriber", m, now)
			if part == 1 && (out.Assembly.Status != AssemblyComplete || out.Assembly.Text != "hello world") {
				t.Fatalf("real segments %#v", out)
			}
		}
	}
}

func TestCompletedDedupExpiryDoesNotInvalidateDisplayedMessage(t *testing.T) {
	a := NewAssembler(Config{Lifetime: time.Second})
	now := time.Unix(100, 0)
	a.Add("scope", segment(1, "hello "), now)
	full := a.Add("scope", segment(2, "world"), now)
	if expired := a.Expire(now.Add(time.Second)); len(expired) != 0 {
		t.Fatal("completed display was invalidated by dedup expiry")
	}
	if a.Stats().Assemblies != 0 || a.Stats().Bytes != 0 {
		t.Fatal("completed dedup state retained")
	}
	a.Add("scope", segment(1, "new "), now.Add(time.Second))
	a.Forget(full.Assembly.ID)
	// An old ID must not discard a later reuse of the same concatenation reference.
	if a.Stats().Assemblies != 1 {
		t.Fatal("old ID forgot a new group")
	}
	pending := a.Add("scope", segment(1, "new "), now.Add(time.Second))
	a.Forget(pending.Assembly.ID)
	if a.Stats().Assemblies != 0 || a.Stats().Bytes != 0 {
		t.Fatal("Forget retained content")
	}
	if last := a.Add("scope", segment(2, "world"), now.Add(time.Second)); last.Assembly.Status == AssemblyComplete {
		t.Fatal("discarded contributor was borrowed")
	}
}
