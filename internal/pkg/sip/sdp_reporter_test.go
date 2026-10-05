package sip

import (
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/stretchr/testify/require"
)

func diagnosticReporter(t *testing.T) (*SDPParseCounters, *SDPDiagnosticReporter, *[]map[string]any) {
	t.Helper()
	logger.UseFile(io.Discard)
	t.Cleanup(logger.Enable)
	c := &SDPParseCounters{}
	r := NewSDPDiagnosticReporter(c, SDPBufferPath)
	var records []map[string]any
	r.warn = func(message string, args ...any) {
		record := map[string]any{"message": message}
		for i := 0; i < len(args); i += 2 {
			record[args[i].(string)] = args[i+1]
		}
		records = append(records, record)
	}
	return c, r, &records
}

func TestSDPDiagnosticReporterAggregatesSanitizedReasons(t *testing.T) {
	c, r, records := diagnosticReporter(t)
	c.Observe(ParseSDPResult("c=IN IP4 192.0.2.1\nm=audio 8000 RTP/AVP 0\nm=invalid", 32))
	c.Observe(ParseSDPResult("c=IN IP4 private.invalid\nm=audio 8000 RTP/AVP 0", 32))
	c.Observe(ParseSDPResult("c=IN IP4 192.0.2.1\nm=audio 8000 RTP/AVP 0\nm=video 9000 RTP/AVP 96", 2))
	r.Report(time.Unix(100, 0))
	require.Len(t, *records, 1)
	record := (*records)[0]
	require.Equal(t, uint64(3), record["incomplete"])
	require.Equal(t, uint64(2), record["partial"])
	require.Equal(t, uint64(1), record["failed"])
	require.Equal(t, uint64(1), record["resource_limited"])
	require.Equal(t, map[SDPReason]uint64{SDPMediaInvalid: 1, SDPConnectionInvalid: 1, SDPConnectionMissing: 1, SDPEndpointLimit: 2}, record["reasons"])
	require.Equal(t, "voip-buffer", record["reporting_path"])
	// Every field is either a fixed public category or aggregate numeric value.
	for name := range record {
		require.Contains(t, []string{"message", "reporting_path", "bodies", "incomplete", "partial", "failed", "resource_limited", "diagnostics_omitted", "reasons", "suppressed", "suppressed_total", "final"}, name)
	}
	r.Flush()
	require.Len(t, *records, 1, "shutdown must not repeat an already published aggregate")
}

func TestSDPDiagnosticReporterRetainsThrottledOccurrences(t *testing.T) {
	c, r, records := diagnosticReporter(t)
	bad := ParseSDPResult("m=audio 8000 RTP/AVP 0", 32)
	start := time.Unix(100, 0)
	c.Observe(bad)
	r.Report(start)
	for range 3 {
		c.Observe(bad)
	}
	r.Report(start.Add(time.Second))
	r.Report(start.Add(2 * time.Second))
	require.Len(t, *records, 1)
	require.Equal(t, SDPReportStats{Warnings: 1, Suppressed: 3}, r.Stats())
	r.Report(start.Add(SDPWarningInterval))
	require.Len(t, *records, 2)
	require.Equal(t, uint64(3), (*records)[1]["incomplete"])
	require.Equal(t, uint64(3), (*records)[1]["suppressed"])
	require.Equal(t, uint64(3), (*records)[1]["suppressed_total"])
	c.Observe(bad)
	r.Flush()
	require.Len(t, *records, 3)
	require.Equal(t, true, (*records)[2]["final"])
	require.Equal(t, uint64(5), c.Snapshot().Failures)
}

func TestSDPDiagnosticReporterBodyLimitAndOmittedReasons(t *testing.T) {
	c, r, records := diagnosticReporter(t)
	c.Observe(ParseSDPResult(strings.Repeat("x", MaxMessageSize+1), 32))
	c.Observe(ParseSDPResult(strings.Repeat("m=invalid\n", MaxSDPDiagnostics+10), 32))
	r.Flush()
	require.Len(t, *records, 1)
	require.Equal(t, uint64(1), (*records)[0]["resource_limited"])
	require.Equal(t, uint64(10), (*records)[0]["diagnostics_omitted"])
	require.Equal(t, map[SDPReason]uint64{SDPBodyLimit: 1, SDPMediaInvalid: MaxSDPDiagnostics + 10}, (*records)[0]["reasons"], "reason accounting includes discarded diagnostic detail")
}

func TestSDPDiagnosticReporterValidInactiveAndDisabled(t *testing.T) {
	c, r, records := diagnosticReporter(t)
	for _, body := range []string{"c=IN IP4 192.0.2.1\nm=audio 8000 RTP/AVP 0", "c=IN IP4 192.0.2.1\nm=audio 0 RTP/AVP 0", "c=IN IP4 0.0.0.0\nm=audio 8000 RTP/AVP 0", "c=IN IP4 192.0.2.1\nm=audio 8000 RTP/AVP 0\na=inactive"} {
		c.Observe(ParseSDPResult(body, 32))
	}
	r.Report(time.Now())
	r.Flush()
	require.Empty(t, *records)
	logger.Disable()
	c.Observe(ParseSDPResult("m=invalid", 32))
	r.Flush()
	require.Empty(t, *records)
	logger.UseFile(io.Discard)
	r.Flush()
	require.Len(t, *records, 1, "normal logger re-enablement preserves aggregate accounting")
	r.Disable()
	c.Observe(ParseSDPResult("m=invalid", 32))
	r.Flush()
	require.Len(t, *records, 1, "delegated reporting owner remains silent")
}

func TestSDPParseCountersConcurrentCoherentSnapshots(t *testing.T) {
	var c SDPParseCounters
	partial := ParseSDPResult("c=IN IP4 192.0.2.1\nm=audio 8000 RTP/AVP 0\nm=invalid", 32)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 1000 {
				c.Observe(partial)
			}
		}()
	}
	for range 1000 {
		s := c.Snapshot()
		require.Equal(t, s.Bodies, s.Failures)
		require.Equal(t, s.Failures, s.Partial)
		require.Equal(t, s.Failures, s.Reasons[SDPMediaInvalid])
	}
	workers.Wait()
	require.Equal(t, uint64(8000), c.Snapshot().Bodies)
}

func TestSDPDiagnosticReporterConcurrentReportsPreserveCounts(t *testing.T) {
	c, r, records := diagnosticReporter(t)
	bad := ParseSDPResult("m=invalid", 32)
	start := time.Unix(100, 0)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				c.Observe(bad)
				r.Report(start)
				_ = r.Stats()
			}
		}()
	}
	workers.Wait()
	r.Report(start.Add(SDPWarningInterval))
	var incomplete uint64
	for _, record := range *records {
		incomplete += record["incomplete"].(uint64)
	}
	require.Equal(t, uint64(800), incomplete)
	require.LessOrEqual(t, len(*records), 2)
	require.Equal(t, uint64(len(*records)), r.Stats().Warnings)
	before := len(*records)
	r.Flush()
	require.Len(t, *records, before)
}

func TestSDPDiagnosticLogIOCannotBlockCounters(t *testing.T) {
	c, r, _ := diagnosticReporter(t)
	bad := ParseSDPResult("m=invalid", 32)
	c.Observe(bad)
	entered, release, reported := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.warn = func(string, ...any) { close(entered); <-release }
	go func() { defer close(reported); r.Flush() }()
	<-entered
	observed := make(chan struct{})
	go func() { defer close(observed); c.Observe(bad); _ = c.Snapshot() }()
	select {
	case <-observed:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("packet counters blocked by diagnostic log writer")
	}
	close(release)
	<-reported
}
