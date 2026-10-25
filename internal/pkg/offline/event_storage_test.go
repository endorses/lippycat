package offline

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func eventStorageEnvelope(sequence uint64) events.Envelope {
	env := events.Envelope{Timestamp: time.Unix(1700000000, int64(sequence)).UTC(), NodeID: "offline-node", ProducerSessionID: "offline-session", EventSequence: sequence,
		UID: "Cflow", CommunityID: "1:flow", CaptureScope: events.CaptureScopeFull,
		Flow:       events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 40000, DestinationPort: 53},
		Provenance: events.SourceProvenance{CaptureSource: "pcap", InputFile: "input.pcap", ProcessorNodeIDs: []string{"processor"}}}
	env.EventID = events.DeliveryEventID(env.NodeID, env.ProducerSessionID, sequence)
	return env
}

func eventStorageDNS(sequence uint64) events.DNSEvent {
	e := events.NewDNSEvent(eventStorageEnvelope(sequence))
	e.Query, e.QClass, e.QType = fmt.Sprintf("query-%d.example.test", sequence), 1, 1
	return e
}

func eventStorageDataset(t *testing.T, count int) (*Storage, *diskEventDataset) {
	t.Helper()
	s := newTestStorage(t)
	b, err := s.NewEventBuilder(7)
	require.NoError(t, err)
	for i := 1; i <= count; i++ {
		require.NoError(t, b.Append(context.Background(), eventStorageDNS(uint64(i))))
		// Arrival metadata is persisted immediately. No offset or event is
		// retained per row, even after the equivalent live ring would evict it.
		require.Equal(t, uint64(eventDatasetMemory), s.Resources().InFlightBytes)
	}
	value, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := value.(*diskEventDataset)
	t.Cleanup(func() {
		require.NoError(t, d.Close())
		require.NoError(t, s.Close())
	})
	return s, d
}

func TestEventStorageCompleteHistoryDiskQueryAndSnapshotLeases(t *testing.T) {
	s, d := eventStorageDataset(t, 4097)
	require.EqualValues(t, 4097, d.Count())
	require.EqualValues(t, eventStreamHeaderBytes+4097*eventOffsetBytes, d.offsetBytes)
	base := s.Resources()
	all, err := AllEvents(context.Background(), d, Token{Dataset: 7, Query: 1})
	require.NoError(t, err)
	require.True(t, all.(*diskEventQuery).identity)
	require.Empty(t, all.(*diskEventQuery).path)
	require.Equal(t, base.DiskBytes, s.Resources().DiskBytes)
	predicate, err := eventquery.Compile("query:query-1.example.test OR query:query-4097.example.test")
	require.NoError(t, err)
	descriptions := []string{"query:query-1.example.test OR query:query-4097.example.test"}
	filtered, err := d.Query(context.Background(), EventQuerySpec{Token: Token{Dataset: 7, Query: 2}, Description: descriptions, Match: predicate})
	require.NoError(t, err)
	descriptions[0] = "changed"
	require.NotEqual(t, descriptions, filtered.(*diskEventQuery).description)
	require.EqualValues(t, 2, filtered.Count())
	require.EqualValues(t, eventQueryHeaderBytes+2*eventQueryEntryBytes, filtered.(*diskEventQuery).bytes)
	page, err := filtered.Page(context.Background(), PageRequest{Token: Token{Dataset: 7, Query: 2, Request: 99}, Row: 0, Limit: 20, MaxBytes: 16 << 10})
	require.NoError(t, err)
	require.Len(t, page.Rows, 2)
	require.Equal(t, EventRowID(1), page.Rows[0].ID)
	require.Equal(t, EventRowID(4097), page.Rows[1].ID)
	require.Equal(t, eventStorageDNS(4097), page.Rows[1].Event)
	copyOfPage := page
	require.NoError(t, page.Close())
	require.NoError(t, copyOfPage.Close())
	// A distant read remains available after all earlier page leases close.
	detail, err := d.Detail(context.Background(), Token{Dataset: 7}, 4097)
	require.NoError(t, err)
	require.Equal(t, eventStorageDNS(4097), detail.Record.Event)
	copyOfDetail := *detail
	require.NoError(t, detail.Close())
	require.NoError(t, copyOfDetail.Close())
	require.NoError(t, all.Close())
	require.NoError(t, filtered.Close())
	require.Equal(t, base, s.Resources())
	require.LessOrEqual(t, s.Peaks().MemoryBytes, s.limits.CacheBytes)

	var actual uint64
	entries, err := os.ReadDir(d.dir)
	require.NoError(t, err)
	info, err := os.Stat(d.dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	for _, entry := range entries {
		info, err := entry.Info()
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
		actual += uint64(info.Size())
	}
	require.Equal(t, actual, s.Resources().DiskBytes)
}

func eventStorageKinds() []events.Event {
	env := eventStorageEnvelope(1)
	conn := events.NewConnEvent(env)
	conn.Service, conn.Duration, conn.State = "dns", time.Second, "SF"
	dns := eventStorageDNS(1)
	dns.Answers, dns.TTLs, dns.IsResponse = []string{"192.0.2.7"}, []time.Duration{time.Minute}, true
	tls := events.NewTLSEvent(env)
	tls.ServerName, tls.Version, tls.ClientHelloCount, tls.ECHOfferedCount = "public.example", "TLS 1.3", 2, 1
	http := events.NewHTTPEvent(env)
	http.Method, http.URI, http.Headers = "GET", "/safe", map[string][]string{"x-test": {"original"}}
	smtp := events.NewSMTPEvent(env)
	smtp.MailFrom, smtp.Recipients, smtp.Subject = "sender@example.test", []string{"recipient@example.test"}, "policy-approved metadata"
	file := events.NewFileMetadataEvent(env)
	file.FileID, file.MIMEType, file.SeenBytes = "Fone", "text/plain", 123
	dhcp := events.NewDHCPEvent(env)
	dhcp.Operation, dhcp.MessageType, dhcp.HardwareType = 1, 1, 1
	dhcp.HardwareAddress = []byte{0, 1, 2, 3, 4, 5}
	dhcp.ClientAddress, dhcp.OfferedAddress, dhcp.NextServerAddress, dhcp.RelayAddress = netip.IPv4Unspecified(), netip.IPv4Unspecified(), netip.IPv4Unspecified(), netip.IPv4Unspecified()
	dhcp.Hostname, dhcp.Association = "host", events.AssociationRequest
	ntp := events.NewNTPEvent(env)
	ntp.Version, ntp.Mode, ntp.Association = 4, 3, events.AssociationRequest
	host := events.NewKnownHostEvent(env)
	host.Host, host.Evidence = env.Flow.SourceAddress, events.EvidenceUDPBidirectional
	service := events.NewKnownServiceEvent(env)
	service.Host, service.Port, service.Transport, service.Protocol, service.Evidence = env.Flow.DestinationAddress, 53, 17, "dns", events.EvidenceDNSExchange
	radius := events.NewRADIUSEvent(env)
	radius.Code, radius.Identifier, radius.Length, radius.Attributes = 1, 4, 20, []string{"1:hex:616c696365"}
	return []events.Event{conn, dns, tls, http, smtp, file, dhcp, ntp, host, service, radius, noticefixture.Event()}
}

func TestEventStorageAllMetadataKindsDuplicateAndAmendedIdentity(t *testing.T) {
	s := newTestStorage(t)
	b, err := s.NewEventBuilder(8)
	require.NoError(t, err)
	want := eventStorageKinds()
	for _, event := range want {
		require.NoError(t, b.Append(context.Background(), event))
	}
	http := want[3].(events.HTTPEvent)
	// Mutating the input after Append cannot amend the preceding disk snapshot.
	http.Headers["x-test"][0] = "amended"
	http.URI = "/amended"
	require.NoError(t, b.Append(context.Background(), http))
	want[3] = func() events.HTTPEvent {
		e := http
		e.Headers, e.URI = map[string][]string{"x-test": {"original"}}, "/safe"
		return e
	}()
	want = append(want, http)
	value, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := value.(*diskEventDataset)
	defer func() { require.NoError(t, d.Close()); require.NoError(t, s.Close()) }()
	require.NoError(t, b.Close(), "builder ownership transfers at Finish")
	q, err := AllEvents(context.Background(), d, Token{Dataset: 8, Query: 1})
	require.NoError(t, err)
	var row uint64
	err = q.Iterate(context.Background(), func(record EventRecord) error {
		row++
		require.EqualValues(t, row, record.ID)
		require.Equal(t, want[row-1], record.Event)
		return nil
	})
	require.NoError(t, err)
	require.EqualValues(t, len(want), row)
	first, err := d.Detail(context.Background(), Token{Dataset: 8}, 4)
	require.NoError(t, err)
	last, err := d.Detail(context.Background(), Token{Dataset: 8}, EventRowID(len(want)))
	require.NoError(t, err)
	require.Equal(t, first.Record.Event.Envelope().EventID, last.Record.Event.Envelope().EventID)
	require.NotEqual(t, first.Record.Event.(events.HTTPEvent).URI, last.Record.Event.(events.HTTPEvent).URI)
	require.NoError(t, first.Close())
	require.NoError(t, last.Close())
	require.NoError(t, q.Close())
}

func TestEventStorageRejectsContentInvalidInputsAndPoisonsPrefix(t *testing.T) {
	for name, invalid := range map[string]events.Event{
		"content": events.NewFileContentEvent(eventStorageEnvelope(1)),
		"nil":     nil, "typed nil": (*events.DNSEvent)(nil),
		"identity":     events.NewDNSEvent(events.Envelope{}),
		"record limit": func() events.Event { e := eventStorageDNS(2); e.Query = strings.Repeat("x", 32<<10); return e }(),
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStorage(t)
			b, err := s.NewEventBuilder(1)
			require.NoError(t, err)
			require.NoError(t, b.Append(context.Background(), eventStorageDNS(1)))
			require.Error(t, b.Append(context.Background(), invalid))
			_, err = b.Finish(context.Background())
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(b.d.dir, "events.manifest"))
			require.True(t, errors.Is(err, os.ErrNotExist))
			require.NoError(t, b.Abort())
			require.NoError(t, b.Abort())
			require.Zero(t, s.Resources().DiskBytes)
			require.Zero(t, s.Resources().InFlightBytes)
			require.NoError(t, s.Close())
		})
	}
}

func TestEventStorageEmptyAndRequestBounds(t *testing.T) {
	_, d := eventStorageDataset(t, 0)
	q, err := AllEvents(context.Background(), d, Token{Dataset: 7, Query: 3})
	require.NoError(t, err)
	require.Zero(t, q.Count())
	page, err := q.Page(context.Background(), PageRequest{Token: q.Token(), Limit: 1})
	require.NoError(t, err)
	require.Empty(t, page.Rows)
	require.NoError(t, page.Close())
	_, err = d.Detail(context.Background(), Token{Dataset: 7}, 0)
	require.Error(t, err)
	_, err = d.Query(context.Background(), EventQuerySpec{Token: Token{Dataset: 8}})
	require.Error(t, err)
	_, err = d.Detail(context.Background(), Token{Dataset: 8}, 1)
	require.Error(t, err)
	_, err = q.Page(context.Background(), PageRequest{Token: Token{Dataset: 7, Query: 4}})
	require.Error(t, err)
	_, err = q.Page(context.Background(), PageRequest{Token: q.Token(), Row: 1})
	require.Error(t, err)
	require.Error(t, q.Iterate(context.Background(), nil))
	require.NoError(t, q.Close())
}

func eventStorageWritable(t *testing.T, file *os.File) *os.File {
	t.Helper()
	f, err := os.OpenFile(file.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	return f
}

func TestEventStorageCorruptionIsExplicitAndReleasesReservations(t *testing.T) {
	for _, corruption := range []string{"data length", "offset length", "offset", "frame version", "frame row", "checksum", "protobuf", "manifest", "stream header"} {
		t.Run(corruption, func(t *testing.T) {
			s, d := eventStorageDataset(t, 2)
			data, offsets := eventStorageWritable(t, d.data), eventStorageWritable(t, d.offsets)
			switch corruption {
			case "data length":
				require.NoError(t, data.Truncate(int64(d.dataBytes-1)))
			case "offset length":
				require.NoError(t, offsets.Truncate(int64(d.offsetBytes-1)))
			case "offset":
				_, err := offsets.WriteAt(make([]byte, 8), eventStreamHeaderBytes)
				require.NoError(t, err)
			case "frame version":
				_, err := data.WriteAt([]byte{255}, eventStreamHeaderBytes+8)
				require.NoError(t, err)
			case "frame row":
				_, err := data.WriteAt([]byte{2}, eventStreamHeaderBytes+16)
				require.NoError(t, err)
			case "checksum":
				_, err := data.WriteAt([]byte{255}, eventStreamHeaderBytes+eventFrameBytes)
				require.NoError(t, err)
			case "protobuf":
				var entry [eventOffsetBytes]byte
				_, err := offsets.ReadAt(entry[:], eventStreamHeaderBytes)
				require.NoError(t, err)
				payload := make([]byte, int(binary.LittleEndian.Uint64(entry[8:]))-eventFrameBytes)
				_, err = data.ReadAt(payload, eventStreamHeaderBytes+eventFrameBytes)
				require.NoError(t, err)
				payload[0] = 0 // invalid protobuf tag, with a valid frame checksum
				header := eventFrame(1, payload)
				_, err = data.WriteAt(header[:], eventStreamHeaderBytes)
				require.NoError(t, err)
				_, err = data.WriteAt(payload, eventStreamHeaderBytes+eventFrameBytes)
				require.NoError(t, err)
			case "manifest":
				_, err := eventStorageWritable(t, d.manifest).WriteAt([]byte{255}, 8)
				require.NoError(t, err)
			case "stream header":
				_, err := offsets.WriteAt([]byte{255}, 8)
				require.NoError(t, err)
			}
			before := s.Resources()
			_, err := d.Detail(context.Background(), Token{Dataset: 7}, 1)
			require.Error(t, err)
			require.Equal(t, before, s.Resources())
		})
	}
}

func TestEventStorageConfiguredAndPhysicalWriteFailuresNeverPublish(t *testing.T) {
	for _, stage := range []string{"disk limit", "write", "flush", "physical full"} {
		t.Run(stage, func(t *testing.T) {
			s := newTestStorage(t)
			packet := testStorageDataset(t, s)
			packetBytes := s.Resources().DiskBytes
			b, err := s.NewEventBuilder(2)
			require.NoError(t, err)
			switch stage {
			case "disk limit":
				s.limits.DiskBytes = s.Resources().DiskBytes + eventFrameBytes
			case "write":
				require.NoError(t, b.d.data.Close())
			case "physical full":
				full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
				if err != nil {
					require.NoError(t, b.Abort())
					require.NoError(t, packet.Close())
					require.NoError(t, s.Close())
					t.Skip("/dev/full is unavailable")
				}
				require.NoError(t, b.d.data.Close())
				b.d.data = full
			}
			err = b.Append(context.Background(), eventStorageDNS(1))
			if stage == "flush" {
				require.NoError(t, err)
				require.NoError(t, b.d.offsets.Close())
			} else {
				require.Error(t, err)
			}
			_, err = b.Finish(context.Background())
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(b.d.dir, "events.manifest"))
			require.True(t, errors.Is(err, os.ErrNotExist))
			cleanupErr := b.Abort()
			if stage == "write" || stage == "flush" {
				require.Error(t, cleanupErr, "closed descriptor errors remain observable")
			} else {
				require.NoError(t, cleanupErr)
			}
			require.NoError(t, b.Abort())
			require.Equal(t, packetBytes, s.Resources().DiskBytes)
			require.NoError(t, packet.Close())
			require.NoError(t, s.Close())
		})
	}
}

func TestEventStorageDecodePreflightBoundsCollectionsBeforeAllocation(t *testing.T) {
	e := eventStorageDNS(1)
	e.Answers = make([]string, protoadapter.MaxCollectionEntries)
	wire, err := protoadapter.ToProto(e)
	require.NoError(t, err)
	payload, err := proto.Marshal(wire)
	require.NoError(t, err)
	_, err = eventDecodeMemory(payload, (&eventsv1.ProtocolEvent{}).ProtoReflect().Descriptor(), 32<<10)
	require.Error(t, err, "many empty members still need decoded slice memory")
	_, err = eventDecodeMemory([]byte{0}, wire.ProtoReflect().Descriptor(), 1<<20)
	require.Error(t, err)
}
