//go:build tui || all

package tui

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func indexOfflineLocatorCandidate(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
	cfg.locatorOrdering = true
	return indexOfflineDataset(ctx, storage, generation, cfg, report)
}

// The complete oracle compares order, packet IDs, source attribution, details,
// queries, export, calls and normalized deterministic event envelopes. Flow UIDs
// retain the legacy oracle's bijective comparison because their seeds are random.
func TestOfflineLocatorIndexerOrderingOracle(t *testing.T) {
	for _, mode := range []string{"direct", "merge", "external"} {
		for _, identity := range []string{"", "caller-owned-input"} {
			t.Run(fmt.Sprintf("%s/identity=%s", mode, identity), func(t *testing.T) {
				paths := writeLocatorSIPFixtures(t, mode)
				cfg := OfflineAnalysisConfig{Inputs: paths, VoIP: true, EventCapacity: 64, MaxCalls: 64, SIPConfig: *voip.GetConfig(), Analysis: LocalEventAnalysisOptions{InputIdentity: identity}}
				runOfflineCompactOracle(t, cfg, func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
					session, err := indexOfflineLocatorCandidate(ctx, storage, generation, cfg, report)
					if err != nil {
						return session, err
					}
					if len(session.Calls) != 1 || session.Calls[0].CallID != "locator-call" || session.Dataset.Statistics().Protocols["SIP"] == 0 {
						return session, fmt.Errorf("locator replay did not finalize the TCP SIP call")
					}
					if len(session.EventStore.Events()) == 0 {
						return session, fmt.Errorf("locator fixture emitted no deterministic events")
					}
					return session, nil
				})
			})
		}
	}
}

func writeLocatorSIPFixtures(t *testing.T, mode string) []string {
	t.Helper()
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:bob@example.com>\r\nCall-ID: locator-call\r\nContent-Length: 0\r\n\r\n")
	split := len(message) / 2
	payloads := [][]byte{message[:split], message[split:], []byte("x\r\n"), message}
	seqs := []uint32{100, uint32(100 + split), 1000, 1100}
	order := []int{0, 1, 2, 3}
	if mode == "external" {
		order = []int{0, 2, 3, 1}
	} // Final record regresses after all earlier scan output.
	path := filepath.Join(t.TempDir(), "sip.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriterNanos(f)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeRaw))
	for _, i := range order {
		env := offlineSIPPacket(t, seqs[i], payloads[i], time.Unix(1700000000+int64(i), 123))
		packet := env.Packet()
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: env.CaptureTime, CaptureLength: len(packet.Data()), Length: len(packet.Data())}, packet.Data()))
	}
	require.NoError(t, f.Close())
	if mode == "merge" {
		return []string{path, path}
	} // Equal timestamps and duplicate arguments are distinct replay domains.
	return []string{path}
}

func TestOfflineLocatorIndexerScanBeforeAnalysis(t *testing.T) {
	paths := writeLocatorSIPFixtures(t, "direct")
	var phases []string
	cfg := OfflineAnalysisConfig{Inputs: paths, locatorOrdering: true, EventCapacity: 32}
	session, err := indexOfflineDatasetObserved(context.Background(), testOfflineStorage(t), 73, cfg, nil, func(phase string, _ time.Duration) { phases = append(phases, phase) })
	require.NoError(t, err)
	require.NoError(t, session.Close())
	position := func(phase string) int {
		for i, p := range phases {
			if p == phase {
				return i
			}
		}
		t.Fatalf("missing phase %s in %v", phase, phases)
		return -1
	}
	require.Less(t, position("scan"), position("identity"))
	require.Less(t, position("identity"), position("analysis_setup"))
	require.Less(t, position("analysis_setup"), position("analysis_and_storage"))
}

func TestOfflineLocatorIndexerPrivateOracle(t *testing.T) {
	path := os.Getenv("LIPPYCAT_BENCH_PCAP")
	if path == "" {
		t.Skip("set LIPPYCAT_BENCH_PCAP for private-capture locator differential oracle")
	}
	cfg := FreezeOfflineOpen([]string{path}, "", 10000).Config
	runOfflineCompactOracle(t, cfg, indexOfflineLocatorCandidate)
}

// Renaming after preparation proves identity and replay use the scanned owned
// input, rather than reopening its original pathname for a separate hash pass.
func TestOfflineLocatorIndexerScannedIdentitySurvivesRename(t *testing.T) {
	paths := writeLocatorSIPFixtures(t, "direct")
	identity, err := events.OfflineInputIdentityContext(context.Background(), paths)
	require.NoError(t, err)
	cfg := OfflineAnalysisConfig{Inputs: paths, EventCapacity: 32}
	baseline, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 74, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, baseline.Close()) }()
	cfg.locatorOrdering = true
	renamed := false
	candidate, err := indexOfflineDatasetObserved(context.Background(), testOfflineStorage(t), 75, cfg, nil, func(phase string, _ time.Duration) {
		if phase == "scan" {
			require.NoError(t, os.Rename(paths[0], paths[0]+".renamed"))
			renamed = true
		}
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, candidate.Close()) }()
	require.True(t, renamed)
	require.Equal(t, baseline.Dataset.Count(), candidate.Dataset.Count())
	a, b := baseline.EventStore.Events(), candidate.EventStore.Events()
	require.NotEmpty(t, a)
	require.Len(t, b, len(a))
	for i := range a {
		require.Equal(t, a[i].Event.Envelope().EventID, b[i].Event.Envelope().EventID, "scan digest identity %s", identity)
	}
}

func TestOfflineLocatorIndexerBackingAndEmptyOracle(t *testing.T) {
	for _, mode := range []string{"snapshot", "gzip", "bpf-empty", "empty"} {
		t.Run(mode, func(t *testing.T) {
			paths := writeLocatorSIPFixtures(t, "direct")
			cfg := OfflineAnalysisConfig{Inputs: paths, EventCapacity: 32}
			switch mode {
			case "snapshot":
				cfg.BackingPolicy = offline.BackingPolicy("snapshot")
			case "gzip":
				data, err := os.ReadFile(paths[0])
				require.NoError(t, err)
				f, err := os.Create(paths[0] + ".gz")
				require.NoError(t, err)
				gz := gzip.NewWriter(f)
				_, err = gz.Write(data)
				require.NoError(t, err)
				require.NoError(t, gz.Close())
				require.NoError(t, f.Close())
				cfg.Inputs = []string{paths[0] + ".gz"}
			case "bpf-empty":
				cfg.BPFFilter = "udp"
			case "empty":
				require.NoError(t, os.Truncate(paths[0], 24))
			}
			runOfflineCompactOracle(t, cfg, indexOfflineLocatorCandidate)
		})
	}
}

func TestOfflineLocatorIndexerScanFailurePreventsAnalysis(t *testing.T) {
	paths := writeLocatorSIPFixtures(t, "direct")
	info, err := os.Stat(paths[0])
	require.NoError(t, err)
	require.NoError(t, os.Truncate(paths[0], info.Size()-1))
	var phases []string
	var ready bool
	session, err := indexOfflineDatasetObserved(context.Background(), testOfflineStorage(t), 76, OfflineAnalysisConfig{Inputs: paths, locatorOrdering: true, EventCapacity: 32}, func(p offline.Progress) { ready = ready || p.State == offline.Ready }, func(phase string, _ time.Duration) { phases = append(phases, phase) })
	require.Error(t, err)
	require.Nil(t, session)
	require.NotContains(t, phases, "analysis_setup")
	require.NotContains(t, phases, "analysis_and_storage")
	require.False(t, ready)
}
