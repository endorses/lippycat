package logstream

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logschema"
	"github.com/stretchr/testify/require"
)

func dnsRecord(t *testing.T) Record {
	t.Helper()
	schema, _ := logschema.ByName("dns")
	values := make([]any, len(schema.Fields))
	for i := range values {
		values[i] = Unset
	}
	values[0], values[1] = time.Unix(1_700_000_000, 125_000_000).UTC(), "Ctest"
	values[2], values[9] = netip.MustParseAddr("192.0.2.1"), "a\tb\\c\n"
	values[21], values[22], values[23] = []string{"one", "two"}, []time.Duration{30 * time.Second, 90*time.Second + 500*time.Millisecond}, false
	r, err := NewRecord("dns", values...)
	require.NoError(t, err)
	return r
}

func TestTSVEncoder(t *testing.T) {
	var output bytes.Buffer
	schema, _ := logschema.ByName("dns")
	enc := newTSVEncoder(&output, schema)
	now := time.Date(2026, 8, 24, 12, 30, 5, 0, time.UTC)
	require.NoError(t, enc.Open(now))
	require.NoError(t, enc.Encode(dnsRecord(t)))
	require.NoError(t, enc.Close(now.Add(time.Second)))
	require.NoError(t, enc.Flush())
	got := output.String()
	require.Contains(t, got, "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n")
	require.Contains(t, got, "#path\tdns\n#open\t2026-08-24-12-30-05\n#fields\tts\tuid")
	require.Contains(t, got, "a\\x09b\\x5cc\\x0a")
	require.Contains(t, got, "\tone,two\t30.000000,90.500000\tF\t")
	require.Contains(t, got, "\t-\t")
	require.True(t, strings.HasSuffix(got, "#close\t2026-08-24-12-30-06\n"))
}

func TestJSONEncoder(t *testing.T) {
	var output bytes.Buffer
	schema, _ := logschema.ByName("dns")
	enc := newJSONEncoder(&output, schema)
	require.NoError(t, enc.Open(time.Now()))
	require.NoError(t, enc.Encode(dnsRecord(t)))
	require.NoError(t, enc.Flush())
	var got map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &got))
	require.Equal(t, "Ctest", got["uid"])
	require.Equal(t, "192.0.2.1", got["id.orig_h"])
	require.Nil(t, got["id.orig_p"])
	require.Equal(t, []any{"one", "two"}, got["answers"])
	require.Equal(t, []any{30.0, 90.5}, got["TTLs"])
}

func TestJSONValueRecursivelyConvertsCollections(t *testing.T) {
	duration := 1500 * time.Millisecond
	value := map[string]any{
		"slice":   []time.Duration{time.Second, duration},
		"array":   [2]time.Duration{2 * time.Second, 3 * time.Second},
		"pointer": &duration,
		"nested":  map[string][]any{"values": {4 * time.Second, netip.MustParseAddr("192.0.2.2")}},
		"nil":     []time.Duration(nil),
		"bytes":   []byte("ok"),
	}

	encoded, err := json.Marshal(jsonValue(value))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(encoded, &got))
	require.Equal(t, []any{1.0, 1.5}, got["slice"])
	require.Equal(t, []any{2.0, 3.0}, got["array"])
	require.Equal(t, 1.5, got["pointer"])
	require.Equal(t, map[string]any{"values": []any{4.0, "192.0.2.2"}}, got["nested"])
	require.Nil(t, got["nil"])
	require.Equal(t, "b2s=", got["bytes"])
}

func TestSinkLazyCreationFlushAndClose(t *testing.T) {
	dir := t.TempDir()
	sink, err := New(Config{Directory: dir, Format: FormatTSV, QueueSize: 8, Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	require.NoError(t, err)
	require.NoError(t, sink.Register(events.KindDNS, "dns", func(events.Event) (Record, bool, error) { return dnsRecord(t), true, nil }))
	require.NoError(t, sink.Start(context.Background()))
	_, err = os.Stat(filepath.Join(dir, "dns.log"))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NoError(t, sink.HandleEvent(context.Background(), events.NewDNSEvent(events.Envelope{})))
	require.NoError(t, sink.Flush(context.Background()))
	data, err := os.ReadFile(filepath.Join(dir, "dns.log"))
	require.NoError(t, err)
	require.Contains(t, string(data), "Ctest")
	require.NoError(t, sink.Close(context.Background()))
	data, err = os.ReadFile(filepath.Join(dir, "dns.log"))
	require.NoError(t, err)
	require.Contains(t, string(data), "#close\t")
	require.Equal(t, uint64(1), sink.Stats().Written)
}

func TestSinkPublishesCompleteRecordsWithoutExplicitFlush(t *testing.T) {
	dir := t.TempDir()
	sink, err := New(Config{Directory: dir, Format: FormatTSV, QueueSize: 8, Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	require.NoError(t, err)
	require.NoError(t, sink.Register(events.KindDNS, "dns", func(events.Event) (Record, bool, error) { return dnsRecord(t), true, nil }))
	require.NoError(t, sink.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })

	require.NoError(t, sink.HandleEvent(context.Background(), events.NewDNSEvent(events.Envelope{})))
	require.Eventually(t, func() bool { return sink.Stats().Written == 1 }, time.Second, time.Millisecond)

	data, err := os.ReadFile(filepath.Join(dir, "dns.log"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 9)
	require.Equal(t, "#separator \\x09", lines[0])
	require.True(t, strings.HasPrefix(lines[len(lines)-1], "1700000000.125000\tCtest\t"))
	require.True(t, strings.HasSuffix(string(data), "\n"), "tailing readers must never see a partial final record")
}

func TestSinkPublishesLowVolumeJSONRecordWithoutExplicitFlush(t *testing.T) {
	dir := t.TempDir()
	sink, err := New(Config{Directory: dir, Format: FormatJSON, QueueSize: 8, Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	require.NoError(t, err)
	require.NoError(t, sink.Register(events.KindDNS, "dns", func(events.Event) (Record, bool, error) { return dnsRecord(t), true, nil }))
	require.NoError(t, sink.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })

	require.NoError(t, sink.HandleEvent(context.Background(), events.NewDNSEvent(events.Envelope{})))
	require.Eventually(t, func() bool { return sink.Stats().Written == 1 }, time.Second, time.Millisecond)

	data, err := os.ReadFile(filepath.Join(dir, "dns.log"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(string(data), "\n"))
	var record map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSuffix(data, []byte{'\n'}), &record))
	require.Equal(t, "Ctest", record["uid"])
}

func TestSinkRotationAndHook(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	var offset atomic.Int64
	var calls atomic.Uint64
	rotated := make(chan string, 1)
	sink, err := New(Config{Directory: dir, Format: FormatJSON, QueueSize: 8, RotateInterval: 20 * time.Millisecond, Now: func() time.Time { return base.Add(time.Duration(offset.Load())) }, PostRotate: func(_ context.Context, path string) error { calls.Add(1); rotated <- path; return nil }})
	require.NoError(t, err)
	require.NoError(t, sink.Register(events.KindDNS, "dns", func(events.Event) (Record, bool, error) { return dnsRecord(t), true, nil }))
	require.NoError(t, sink.Start(context.Background()))
	require.NoError(t, sink.HandleEvent(context.Background(), events.NewDNSEvent(events.Envelope{})))
	require.NoError(t, sink.Flush(context.Background()))
	offset.Store(int64(time.Second))
	select {
	case path := <-rotated:
		require.FileExists(t, path)
		require.Contains(t, filepath.Base(path), "dns-2026-08-24-10-00-01.log")
	case <-time.After(time.Second):
		t.Fatal("rotation hook was not called")
	}
	require.NoError(t, sink.Close(context.Background()))
	require.Equal(t, uint64(1), calls.Load())
}

func TestSinkRotatesExistingLogWhenFormatChanges(t *testing.T) {
	tests := []struct {
		name, existing string
		format         Format
	}{
		{"tsv-to-json", "#separator \\x09\nold-tsv\n", FormatJSON},
		{"json-to-tsv", "{\"uid\":\"old-json\"}\n", FormatTSV},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			active := filepath.Join(dir, "dns.log")
			require.NoError(t, os.WriteFile(active, []byte(tt.existing), 0o640))
			now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
			sink, err := New(Config{Directory: dir, Format: tt.format, QueueSize: 8, Now: func() time.Time { return now }})
			require.NoError(t, err)
			require.NoError(t, sink.Register(events.KindDNS, "dns", func(events.Event) (Record, bool, error) { return dnsRecord(t), true, nil }))
			require.NoError(t, sink.Start(context.Background()))
			require.NoError(t, sink.HandleEvent(context.Background(), events.NewDNSEvent(events.Envelope{})))
			require.NoError(t, sink.Flush(context.Background()))
			require.NoError(t, sink.Close(context.Background()))

			archived := filepath.Join(dir, "dns-2026-08-28-12-00-00.log")
			old, err := os.ReadFile(archived)
			require.NoError(t, err)
			require.Equal(t, tt.existing, string(old))
			current, err := os.ReadFile(active)
			require.NoError(t, err)
			if tt.format == FormatJSON {
				require.NotContains(t, string(current), "#separator")
				for _, line := range bytes.Split(bytes.TrimSpace(current), []byte{'\n'}) {
					require.True(t, json.Valid(line), "invalid JSON line: %q", line)
				}
			} else {
				require.True(t, strings.HasPrefix(string(current), "#separator \\x09\n"))
				require.NotContains(t, string(current), "old-json")
			}
			require.Equal(t, uint64(1), sink.Stats().Rotations)
		})
	}
}

func TestSinkFormatChangeRotationDoesNotOverwriteCollision(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "dns.log")
	firstArchive := filepath.Join(dir, "dns-2026-08-28-12-00-00.log")
	require.NoError(t, os.WriteFile(active, []byte("#separator \\x09\nold-tsv\n"), 0o640))
	require.NoError(t, os.WriteFile(firstArchive, []byte("keep-me"), 0o640))
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	sink, err := New(Config{Directory: dir, Format: FormatJSON, QueueSize: 8, Now: func() time.Time { return now }})
	require.NoError(t, err)
	require.NoError(t, sink.Register(events.KindDNS, "dns", func(events.Event) (Record, bool, error) { return dnsRecord(t), true, nil }))
	require.NoError(t, sink.Start(context.Background()))
	require.NoError(t, sink.HandleEvent(context.Background(), events.NewDNSEvent(events.Envelope{})))
	require.NoError(t, sink.Flush(context.Background()))
	require.NoError(t, sink.Close(context.Background()))

	data, err := os.ReadFile(firstArchive)
	require.NoError(t, err)
	require.Equal(t, "keep-me", string(data))
	data, err = os.ReadFile(filepath.Join(dir, "dns-2026-08-28-12-00-00-1.log"))
	require.NoError(t, err)
	require.Equal(t, "#separator \\x09\nold-tsv\n", string(data))
}

func TestSinkRejectsUnrecognizedExistingLogWithoutModifyingIt(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "dns.log")
	require.NoError(t, os.WriteFile(active, []byte("not a structured log\n"), 0o640))
	sink, err := New(Config{Directory: dir, Format: FormatJSON, QueueSize: 8})
	require.NoError(t, err)
	require.NoError(t, sink.Register(events.KindDNS, "dns", func(events.Event) (Record, bool, error) { return dnsRecord(t), true, nil }))
	require.NoError(t, sink.Start(context.Background()))
	require.NoError(t, sink.HandleEvent(context.Background(), events.NewDNSEvent(events.Envelope{})))
	require.NoError(t, sink.Flush(context.Background()))
	require.Equal(t, uint64(1), sink.Stats().Errors)
	require.NoError(t, sink.Close(context.Background()))
	data, err := os.ReadFile(active)
	require.NoError(t, err)
	require.Equal(t, "not a structured log\n", string(data))
}

func TestSinkQueueFullDrops(t *testing.T) {
	sink, err := New(Config{Directory: t.TempDir(), Format: FormatJSON, QueueSize: 1})
	require.NoError(t, err)
	require.NoError(t, sink.Register(events.KindDNS, "dns", func(events.Event) (Record, bool, error) { return dnsRecord(t), true, nil }))
	require.NoError(t, sink.Start(context.Background()))
	ev := events.NewDNSEvent(events.Envelope{})
	start := time.Now()
	for range 10000 {
		require.NoError(t, sink.HandleEvent(context.Background(), ev))
	}
	require.Less(t, time.Since(start), 2*time.Second)
	require.Greater(t, sink.Stats().Dropped, uint64(0))
	require.NoError(t, sink.Close(context.Background()))
}

func TestNewRecordValidation(t *testing.T) {
	_, err := NewRecord("missing")
	require.Error(t, err)
	_, err = NewRecord("dns", 1)
	require.Error(t, err)
}
