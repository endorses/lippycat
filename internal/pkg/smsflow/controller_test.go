package smsflow

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sms"
)

var observationTime = time.Unix(1_000, 0)

func textMessage(text string) *sms.Message {
	return &sms.Message{Text: text, Status: sms.StatusDecoded, Encoding: sms.EncodingGSM7, Direction: sms.DirectionMO, To: "+12025550123", RPType: 0, TPType: 1, Reference: 17}
}
func partMessage(part uint8, text string) *sms.Message {
	m := textMessage(text)
	m.Reference = part
	m.Concat = &sms.Concatenation{Reference: 123, ReferenceBits: 8, Total: 2, Part: part}
	return m
}
func request(call string, sequence uint64, message *sms.Message) pipeline.SIPResult {
	return pipeline.SIPResult{Timestamp: observationTime, CallID: call, Method: "MESSAGE", CSeqMethod: "MESSAGE", CSeqNumber: sequence, ViaBranch: fmt.Sprintf("z9hG4bK-%s-%d", call, sequence), FromURI: "sip:alice@example.test", ToURI: "sip:bob@example.test", ContentType: "application/vnd.3gpp.sms", SMS: message, Packet: &pipeline.PacketEnvelope{Data: []byte{1, 2, 3}, Source: pipeline.SourceProvenance{NodeID: "hunter", ProducerSessionID: "session", CaptureEpoch: "capture", ObservationDomain: 5, ObservationDomainKnown: true}}}
}
func response(r pipeline.SIPResult, code int) pipeline.SIPResult {
	r.Method = ""
	r.ResponseCode = code
	r.ContentType = ""
	r.SMS = nil
	r.Body = nil
	return r
}
func control(call string, reference uint8) pipeline.SIPResult {
	r := request(call, 1, &sms.Message{Status: sms.StatusControl, Direction: sms.DirectionMT, RPType: 3, Reference: reference})
	r.FromURI, r.ToURI = r.ToURI, r.FromURI
	return r
}

type observation struct {
	label  string
	result pipeline.SIPResult
}
type recorder struct {
	delivered []observation
	discarded []string
}

func (rec *recorder) entry(label string, r pipeline.SIPResult) Entry {
	return Entry{Result: r, Size: 3, Deliver: func(result pipeline.SIPResult) error {
		result.SMS = sms.Clone(result.SMS)
		rec.delivered = append(rec.delivered, observation{label, result})
		return nil
	}, Discard: func() { rec.discarded = append(rec.discarded, label) }}
}
func (rec *recorder) labels() []string {
	var labels []string
	for _, r := range rec.delivered {
		labels = append(labels, r.label)
	}
	return labels
}
func newController(t *testing.T, config Config) *Controller {
	t.Helper()
	c, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}
func process(t *testing.T, c *Controller, entry Entry) bool {
	t.Helper()
	ok, e := c.Process(entry)
	if e != nil {
		t.Fatal(e)
	}
	return ok
}
func expectLabels(t *testing.T, rec *recorder, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(rec.labels(), want) {
		t.Fatalf("delivered %v want %v", rec.labels(), want)
	}
}

func TestDisabledPreservesOutputsWithoutDecisionCache(t *testing.T) {
	c := newController(t, Config{})
	rec := &recorder{}
	for _, status := range []sms.DecodeStatus{sms.StatusDecoded, sms.StatusMalformed, sms.StatusUnsupported, sms.StatusIncomplete, sms.StatusControl} {
		r := request(string(status), 1, textMessage("unmatched"))
		r.SMS.Status = status
		if !process(t, c, rec.entry(string(status), r)) {
			t.Fatal(status)
		}
	}
	a := request("part1", 1, partMessage(1, "hel"))
	b := request("part2", 1, partMessage(2, "lo"))
	process(t, c, rec.entry("first", a))
	if len(rec.delivered) != 6 || rec.delivered[5].result.SMS.Assembly.Status != sms.AssemblyPending {
		t.Fatal("first segment delayed")
	}
	process(t, c, rec.entry("last", b))
	if rec.delivered[6].result.SMS.Assembly.Text != "hello" {
		t.Fatal("disabled assembly missing")
	}
	if c.transactions != nil || c.references != nil || c.controls != nil || c.Enabled() || c.Stats().PendingMessages != 0 {
		t.Fatal("disabled decision state allocated")
	}
}

func TestSingleTextGateResponsesAndDuplicates(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"HELLO"}})
	rec := &recorder{}
	r := request("match", 1, textMessage("say hello"))
	if !process(t, c, rec.entry("request", r)) {
		t.Fatal("match rejected")
	}
	if process(t, c, rec.entry("duplicate", r)) {
		t.Fatal("duplicate forwarded")
	}
	if !process(t, c, rec.entry("response", response(r, 202))) {
		t.Fatal("associated response rejected")
	}
	process(t, c, rec.entry("response duplicate", response(r, 202)))
	bad := request("nonmatch", 1, textMessage("bye"))
	process(t, c, rec.entry("nonmatch", bad))
	process(t, c, rec.entry("nonmatch response", response(bad, 200)))
	expectLabels(t, rec, "request", "response")
	if c.Stats().PendingMessages != 0 || c.Stats().PendingBytes != 0 || c.Stats().Duplicates != 2 {
		t.Fatalf("accounting %#v", c.Stats())
	}
}

func TestMultipartFullGroupReleaseOnceInCaptureOrder(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	first := request("different-call-one", 3, partMessage(1, "hel"))
	first.Timestamp = observationTime.Add(time.Second)
	last := request("different-call-two", 9, partMessage(2, "lo"))
	last.Timestamp = observationTime.Add(2 * time.Second)
	last.SourceIP = "192.0.2.99"
	last.SourcePort = 45000
	// Response-first observations and out-of-order delivery are allowed. Output
	// is ordered by capture timestamp, independent of transaction-map iteration.
	firstResponse := response(first, 200)
	firstResponse.Timestamp = observationTime.Add(3 * time.Second)
	lastResponse := response(last, 202)
	lastResponse.Timestamp = observationTime.Add(4 * time.Second)
	process(t, c, rec.entry("response one", firstResponse))
	process(t, c, rec.entry("response two", lastResponse))
	if process(t, c, rec.entry("last part", last)) {
		t.Fatal("early multipart release")
	}
	if !process(t, c, rec.entry("first part", first)) {
		t.Fatal("cross-boundary match missed")
	}
	expectLabels(t, rec, "first part", "last part", "response one", "response two")
	for _, entry := range rec.delivered {
		if entry.result.SMS != nil && (entry.result.SMS.Assembly.Status != sms.AssemblyComplete || entry.result.SMS.Assembly.Text != "hello") {
			t.Fatalf("completion missing %#v", entry.result.SMS)
		}
	}
	if rec.delivered[0].result.Packet != first.Packet || rec.delivered[1].result.Packet != last.Packet {
		t.Fatal("packet provenance replaced")
	}
	process(t, c, rec.entry("part retransmission", first))
	if len(rec.delivered) != 4 || c.Stats().PendingMessages != 0 || c.Stats().PendingBytes != 0 {
		t.Fatal("group released twice")
	}
}

func TestPartialKeywordNeverReleasesBeforeCompletion(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	process(t, c, rec.entry("first", request("a", 1, partMessage(1, "hello"))))
	if len(rec.delivered) != 0 {
		t.Fatal("partial text admitted")
	}
	process(t, c, rec.entry("last", request("b", 1, partMessage(2, " world"))))
	expectLabels(t, rec, "first", "last")
}

func TestSuppliedCompletionCannotBorrowUnobservedAuthority(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	complete := partMessage(2, "lo")
	complete.Assembly = sms.AssemblyInfo{ID: "upstream", Status: sms.AssemblyComplete, Text: "hello", Received: []uint8{1, 2}}
	process(t, c, rec.entry("supplied complete", request("b", 1, complete)))
	expectLabels(t, rec)
	process(t, c, rec.entry("eligible first", request("a", 1, partMessage(1, "hel"))))
	expectLabels(t, rec, "supplied complete", "eligible first")
}

func TestConflictingRetransmissionPoisonsPendingGroup(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw_%t", raw), func(t *testing.T) {
			c := newController(t, Config{Keywords: []string{"hello"}})
			rec := &recorder{}
			r := request("a", 1, partMessage(1, "hel"))
			if raw {
				r.Body = []byte{1}
			}
			process(t, c, rec.entry("first", r))
			changed := r
			changed.SMS = sms.Clone(r.SMS)
			changed.SMS.Text = "different"
			if raw {
				changed.Body = []byte{2}
				changed.SMS.Text = "hel"
			}
			process(t, c, rec.entry("conflicting", changed))
			process(t, c, rec.entry("last", request("b", 1, partMessage(2, "lo"))))
			expectLabels(t, rec)
			if c.Stats().PendingMessages != 0 {
				t.Fatal("conflicting group retained output")
			}
		})
	}
}

func TestConflictingPositionAcrossTransactionsPoisonsAssembly(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	for _, r := range []pipeline.SIPResult{request("a", 1, partMessage(1, "hel")), request("a-duplicate-position", 2, partMessage(1, "wrong")), request("b", 1, partMessage(2, "lo"))} {
		process(t, c, rec.entry(r.CallID, r))
	}
	expectLabels(t, rec)
	if c.Stats().PendingMessages != 0 {
		t.Fatal("conflict retained references")
	}
}

func TestCurrentAuthorityPreflightRejectsWholeGroup(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	eligible := true
	first := rec.entry("first", request("a", 1, partMessage(1, "hel")))
	first.Current = func() bool { return eligible }
	process(t, c, first)
	eligible = false
	process(t, c, rec.entry("last", request("b", 1, partMessage(2, "lo"))))
	expectLabels(t, rec)
	if len(rec.discarded) != 2 || c.Stats().PendingMessages != 0 {
		t.Fatalf("withdrawn group %#v", rec)
	}
}

func TestControlCorrelationBeforeAndAfterAdmittedText(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprintf("before_%t", before), func(t *testing.T) {
			c := newController(t, Config{Keywords: []string{"hello"}})
			rec := &recorder{}
			data := request("data", 1, textMessage("hello"))
			ack := control("ack", 17)
			if before {
				process(t, c, rec.entry("ack response", response(ack, 200)))
				process(t, c, rec.entry("ack", ack))
				expectLabels(t, rec)
			}
			process(t, c, rec.entry("data", data))
			if !before {
				process(t, c, rec.entry("ack", ack))
				process(t, c, rec.entry("ack response", response(ack, 200)))
			}
			if len(rec.delivered) != 3 {
				t.Fatalf("associated controls missing %v", rec.labels())
			}
			if c.Stats().PendingMessages != 0 {
				t.Fatal("control retained")
			}
		})
	}
}

func TestControlDoesNotBorrowRejectedReportOrAmbiguousReference(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	bad := request("bad", 1, textMessage("bye"))
	process(t, c, rec.entry("negative", bad))
	process(t, c, rec.entry("negative ack", control("bad-ack", 17)))
	// Reusing the small RP reference for several transactions leaves an ambiguity
	// tombstone. A third new message cannot restore old acknowledgement authority.
	for _, call := range []string{"one", "two", "three"} {
		process(t, c, rec.entry(call, request(call, 1, textMessage("hello"))))
	}
	process(t, c, rec.entry("ambiguous ack", control("ambiguous-ack", 17)))
	for _, rpType := range []uint8{0, 1, 6} {
		report := control(fmt.Sprintf("report-%d", rpType), 17)
		report.SMS.RPType = rpType
		process(t, c, rec.entry(report.CallID, report))
	}
	expectLabels(t, rec, "one", "two", "three")
}

func TestControlDirectionsDoNotShareRPReference(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	m := textMessage("hello")
	process(t, c, rec.entry("MO", request("mo", 1, m)))
	wrongDirection := control("wrong", 17)
	wrongDirection.SMS.RPType = 2
	wrongDirection.SMS.Direction = sms.DirectionMO
	process(t, c, rec.entry("wrong ack direction", wrongDirection))
	expectLabels(t, rec, "MO")
	rightDirection := control("right", 17)
	process(t, c, rec.entry("right ack direction", rightDirection))
	expectLabels(t, rec, "MO", "right ack direction")
}

func TestPagerAndUnrelatedCallsRemainOutsidePredicate(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}, MaxPendingMessages: 1})
	rec := &recorder{}
	pager := request("pager", 1, nil)
	pager.ContentType = "text/plain"
	pager.Body = []byte("does not match")
	process(t, c, rec.entry("pager response", response(pager, 202)))
	process(t, c, rec.entry("pager", pager))
	expectLabels(t, rec, "pager response", "pager")
	another := pager
	another.CallID = "another"
	process(t, c, rec.entry("pager cache full", another))
	invite := request("invite", 1, nil)
	invite.Method = "INVITE"
	invite.CSeqMethod = "INVITE"
	process(t, c, rec.entry("invite", invite))
	expectLabels(t, rec, "pager response", "pager", "pager cache full", "invite")
}

func TestScopeTransactionAndCaptureSeparation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*pipeline.SIPResult)
	}{
		{"session", func(r *pipeline.SIPResult) { r.Packet.Source.ProducerSessionID = "different" }},
		{"epoch", func(r *pipeline.SIPResult) { r.Packet.Source.CaptureEpoch = "different" }},
		{"domain", func(r *pipeline.SIPResult) { r.Packet.Source.ObservationDomain++ }},
		{"generation", func(r *pipeline.SIPResult) { r.Packet.Source.CapturePolicyGeneration++ }},
		{"source", func(r *pipeline.SIPResult) { r.Packet.Source.NodeID = "other" }},
		{"subscriber", func(r *pipeline.SIPResult) { r.FromURI = "sip:carol@example.test" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newController(t, Config{Keywords: []string{"hello"}})
			rec := &recorder{}
			a := request("a", 1, partMessage(1, "hel"))
			b := request("b", 1, partMessage(2, "lo"))
			tc.change(&b)
			process(t, c, rec.entry("a", a))
			process(t, c, rec.entry("b", b))
			expectLabels(t, rec)
		})
	}
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	yes := request("reused-call", 1, textMessage("hello"))
	no := request("reused-call", 2, textMessage("bye"))
	process(t, c, rec.entry("yes", yes))
	process(t, c, rec.entry("no", no))
	process(t, c, rec.entry("negative response", response(no, 200)))
	expectLabels(t, rec, "yes")
	// Available Via branches distinguish same-Call-ID, same-CSeq transactions.
	branch := yes
	branch.ViaBranch = "other-branch"
	branch.SMS = textMessage("bye")
	process(t, c, rec.entry("other branch", branch))
	expectLabels(t, rec, "yes")
}

func TestRetentionBudgetsExpiryResetAndShutdown(t *testing.T) {
	for _, config := range []Config{{MaxPendingMessages: 1}, {MaxPendingBytes: 1}} {
		config.Keywords = []string{"hello"}
		c := newController(t, config)
		rec := &recorder{}
		process(t, c, rec.entry("part one", request("a", 1, partMessage(1, "hel"))))
		process(t, c, rec.entry("part two", request("b", 1, partMessage(2, "lo"))))
		expectLabels(t, rec)
		if c.Stats().ResourceLimited == 0 {
			t.Fatal("resource exhaustion missing")
		}
		c.Close()
		if c.Stats().PendingMessages != 0 || c.Stats().PendingBytes != 0 {
			t.Fatal("close retained bytes")
		}
	}
	c := newController(t, Config{Keywords: []string{"hello"}, Assembly: sms.Config{Lifetime: time.Second}})
	rec := &recorder{}
	r := request("a", 1, partMessage(1, "hel"))
	process(t, c, rec.entry("original", r))
	r.Timestamp = observationTime.Add(900 * time.Millisecond)
	process(t, c, rec.entry("duplicate", r))
	c.Expire(observationTime.Add(time.Second))
	if c.Stats().PendingMessages != 0 || c.Stats().PendingBytes != 0 || c.Stats().Transactions != 0 {
		t.Fatal("duplicates extended expiry")
	}
	r = request("b", 1, partMessage(2, "lo"))
	r.Timestamp = observationTime.Add(time.Second)
	process(t, c, rec.entry("late second", r))
	expectLabels(t, rec)
	c.Reset()
	if c.Stats().PendingMessages != 0 || c.Stats().Transactions != 0 {
		t.Fatal("reset retained state")
	}
	process(t, c, rec.entry("after reset", request("new", 1, textMessage("hello"))))
	expectLabels(t, rec, "after reset")
	c.Close()
	process(t, c, rec.entry("after close", request("closed", 1, textMessage("hello"))))
	expectLabels(t, rec, "after reset")
}

func TestExpiredResponseFirstCannotLeaveBorrowableAssembly(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}, Assembly: sms.Config{Lifetime: time.Minute}})
	rec := &recorder{}
	first := request("a", 1, partMessage(1, "hel"))
	process(t, c, rec.entry("early response", response(first, 200)))
	first.Timestamp = observationTime.Add(50 * time.Second)
	process(t, c, rec.entry("first", first))
	last := request("b", 1, partMessage(2, "lo"))
	last.Timestamp = observationTime.Add(70 * time.Second)
	process(t, c, rec.entry("last", last))
	expectLabels(t, rec)
	if c.Stats().PendingMessages != 1 {
		t.Fatalf("expired contributor borrowed %#v", c.Stats())
	}
}

func TestRetainedMetadataOwnershipAndBudget(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	first := request("a", 1, partMessage(1, "hel"))
	first.Headers = map[string]string{"x": "original"}
	first.Body = []byte{1}
	first.SMS.Assembly = sms.AssemblyInfo{Text: "supplied"}
	process(t, c, rec.entry("first", first))
	first.Body[0] = 2
	first.Headers["x"] = "changed"
	first.SMS.Text = "changed"
	process(t, c, rec.entry("last", request("b", 1, partMessage(2, "lo"))))
	if len(rec.delivered) != 2 || rec.delivered[0].result.Headers["x"] != "original" || rec.delivered[0].result.Body[0] != 1 || rec.delivered[0].result.SMS.Text != "hel" {
		t.Fatal("pending metadata was mutable")
	}
	limited := newController(t, Config{Keywords: []string{"hello"}, MaxPendingBytes: 1024})
	r := request("big", 1, partMessage(1, "hel"))
	r.Headers = map[string]string{"large": strings.Repeat("x", 2048)}
	process(t, limited, rec.entry("large metadata", r))
	if limited.Stats().ResourceLimited != 1 || limited.Stats().PendingBytes != 0 {
		t.Fatal("metadata escaped byte budget")
	}
}

func TestMalformedUnsupportedAndUnrelatedReportsCannotMatch(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	rec := &recorder{}
	for _, status := range []sms.DecodeStatus{sms.StatusMalformed, sms.StatusUnsupported, sms.StatusIncomplete} {
		m := textMessage("hello")
		m.Status = status
		process(t, c, rec.entry(string(status), request(string(status), 1, m)))
	}
	// Missing upstream metadata is enriched using the shared decoder, preserving
	// explicit malformed/unavailable status instead of treating binary as a pager.
	r := request("no metadata", 1, nil)
	r.Body = []byte{0, 1}
	process(t, c, rec.entry("malformed raw", r))
	expectLabels(t, rec)
}

func TestCallbackErrorsAndConcurrentLifecycle(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	want := errors.New("output unavailable")
	calls := 0
	ok, e := c.Process(Entry{Result: request("error", 1, textMessage("hello")), Deliver: func(pipeline.SIPResult) error { calls++; return want }})
	if !ok || !errors.Is(e, want) || calls != 1 || c.Stats().PendingMessages != 0 {
		t.Fatalf("delivery error %t %v", ok, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not cancel")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := c.Process(Entry{Result: request(fmt.Sprint(i), 1, textMessage("hello")), Deliver: func(pipeline.SIPResult) error { return nil }})
			if err != nil {
				t.Error(err)
			}
			c.Stats()
			c.Expire(observationTime)
		}(i)
	}
	wg.Wait()
}

func TestRejectedResponseCannotRetainLaterMultipartRequest(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}, MaxPendingBytes: 1})
	rec := &recorder{}
	r := request("a", 1, partMessage(1, "hel"))
	process(t, c, rec.entry("response", response(r, 200)))
	process(t, c, rec.entry("request", r))
	if c.Stats().PendingMessages != 0 || len(rec.discarded) != 2 {
		t.Fatal("already rejected transaction retained later request")
	}
}

func TestSuppliedNegativeAssemblyIsNeverPromoted(t *testing.T) {
	for _, status := range []sms.AssemblyStatus{sms.AssemblyConflict, sms.AssemblyExpired, sms.AssemblyResourceLimited} {
		c := newController(t, Config{Keywords: []string{"hello"}})
		rec := &recorder{}
		first := partMessage(1, "hel")
		first.Assembly.Status = status
		process(t, c, rec.entry("negative", request("a", 1, first)))
		process(t, c, rec.entry("last", request("b", 1, partMessage(2, "lo"))))
		expectLabels(t, rec)
	}
}

func TestUnknownSubscriberOrUnmappedCaptureInputsDoNotJoin(t *testing.T) {
	cases := []struct {
		name              string
		unknownSubscriber bool
		change            func(*pipeline.SIPResult)
	}{
		{name: "unknown subscriber", unknownSubscriber: true, change: func(r *pipeline.SIPResult) {}},
		{name: "unmapped interface", change: func(r *pipeline.SIPResult) { r.Packet.Source.InterfaceIndex = 2 }},
		{name: "unmapped input", change: func(r *pipeline.SIPResult) { r.Packet.Source.InputFile = "other.pcap" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newController(t, Config{Keywords: []string{"hello"}})
			rec := &recorder{}
			first := request("a", 1, partMessage(1, "hel"))
			last := request("b", 1, partMessage(2, "lo"))
			for _, r := range []*pipeline.SIPResult{&first, &last} {
				r.Packet.Source.ObservationDomainKnown = false
				r.Packet.Source.InterfaceIndex = 1
				r.Packet.Source.InputFile = "original.pcap"
				if tc.unknownSubscriber {
					r.FromURI = ""
				}
			}
			tc.change(&last)
			process(t, c, rec.entry("first", first))
			process(t, c, rec.entry("last", last))
			expectLabels(t, rec)
		})
	}
}

func TestCloseStopsLiveExpiryLoopWithoutCancelingParent(t *testing.T) {
	c := newController(t, Config{Keywords: []string{"hello"}})
	stopped := make(chan struct{})
	go func() { c.Run(context.Background()); close(stopped) }()
	c.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Close left expiry timer running")
	}
	// Close is idempotent, including before a subsequent Run invocation.
	c.Close()
	c.Run(context.Background())
}
