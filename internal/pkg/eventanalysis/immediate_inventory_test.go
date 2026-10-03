package eventanalysis

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func assertInventoryBeforeConnectionExpiry(t *testing.T, d *events.Dispatcher, sink *memorySink, hosts, services int) {
	t.Helper()
	require.NoError(t, d.Flush(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var gotHosts, gotServices int
	for _, event := range sink.events {
		switch event.Kind() {
		case events.KindKnownHost:
			gotHosts++
		case events.KindKnownService:
			gotServices++
		case events.KindConn:
			t.Fatal("connection summary emitted before expiry")
		}
	}
	require.Equal(t, hosts, gotHosts)
	require.Equal(t, services, gotServices)
}

func TestInventoryEmitsOnTCPConfirmationBeforeConnectionExpiry(t *testing.T) {
	r, d, sink := inventoryRuntime(t)
	t.Cleanup(func() {
		r.Close()
		require.NoError(t, d.Close(context.Background()))
	})
	source := Source{NodeID: "sensor", CaptureSource: "interface"}
	at := time.Unix(1800000000, 0)
	observe := func(reverse bool, seq, ack uint32, flags, payload string) {
		t.Helper()
		require.NoError(t, r.ObservePacket(source, inventoryTCPPacket(t, "192.0.2.20", "192.0.2.80", reverse, seq, ack, flags, payload, at)))
		at = at.Add(time.Millisecond)
	}
	observe(false, 100, 0, "S", "")
	observe(true, 500, 101, "SA", "")
	assertInventoryBeforeConnectionExpiry(t, d, sink, 0, 0)
	observe(false, 101, 501, "A", "")
	assertInventoryBeforeConnectionExpiry(t, d, sink, 2, 0)
	request := "GET /inventory HTTP/1.1\r\nHost: example.test\r\n\r\n"
	observe(false, 101, 501, "PA", request)
	assertInventoryBeforeConnectionExpiry(t, d, sink, 2, 1)
	observe(true, 501, 101+uint32(len(request)), "PA", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	assertInventoryBeforeConnectionExpiry(t, d, sink, 2, 1)
	// Final lifecycle summaries retain their normal timing and cannot duplicate inventory.
	r.Expire(at.Add(6 * time.Minute))
	require.NoError(t, d.Flush(context.Background()))
	require.Len(t, inventoryEvents(sink), 3)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var connections int
	for _, event := range sink.events {
		if conn, ok := event.(events.ConnEvent); ok {
			connections++
			require.Empty(t, conn.Evidence)
			require.Empty(t, conn.AnalysisScope)
		}
	}
	require.Equal(t, 1, connections)
}

func TestInventoryEmitsOnDNSResponseBeforeConnectionExpiry(t *testing.T) {
	r, d, sink := inventoryRuntime(t)
	t.Cleanup(func() {
		r.Close()
		require.NoError(t, d.Close(context.Background()))
	})
	source := Source{NodeID: "sensor"}
	at := time.Unix(1800000000, 0)
	require.NoError(t, r.ObservePacket(source, dnsInventoryPacket(t, at, false, 17, "example.test")))
	assertInventoryBeforeConnectionExpiry(t, d, sink, 0, 0)
	require.NoError(t, r.ObservePacket(source, dnsInventoryPacket(t, at.Add(time.Millisecond), true, 17, "example.test")))
	assertInventoryBeforeConnectionExpiry(t, d, sink, 2, 1)
	// Additional valid exchanges on the active flow remain deduplicated.
	require.NoError(t, r.ObservePacket(source, dnsInventoryPacket(t, at.Add(2*time.Millisecond), false, 18, "example.test")))
	require.NoError(t, r.ObservePacket(source, dnsInventoryPacket(t, at.Add(3*time.Millisecond), true, 18, "example.test")))
	assertInventoryBeforeConnectionExpiry(t, d, sink, 2, 1)
}
