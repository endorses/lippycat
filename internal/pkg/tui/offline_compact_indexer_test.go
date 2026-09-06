//go:build tui || all

package tui

import (
	"compress/gzip"
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestOfflineCompactIndexerOrderingOracle(t *testing.T) {
	for _, mode := range []string{"direct", "merge", "external"} {
		t.Run(mode, func(t *testing.T) {
			cfg := OfflineAnalysisConfig{Inputs: writeLocatorSIPFixtures(t, mode), VoIP: true, EventCapacity: 64, MaxCalls: 64, SIPConfig: *voip.GetConfig()}
			runOfflineCompactOracle(t, cfg, indexOfflineCompactDataset)
		})
	}
}

func TestOfflineCompactIndexerMultipleBlocksOracle(t *testing.T) {
	paths := writeOrderedBridgeFixtures(t)
	paths = append(paths, paths[0])
	runOfflineCompactOracle(t, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 32, MaxCalls: 32}, indexOfflineCompactDataset)
}

func writeCompactProtocolFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "protocols.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriterNanos(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	packets := [][]byte{
		goldenDNSPacket(t),
		goldenTCPPacket(t, 49153, 8088, []byte("GET /offline HTTP/1.1\r\nHost: example.test\r\nAuthorization: token\r\n\r\n")),
		goldenTCPPacket(t, 49154, 443, goldenTLSClientHello()),
		goldenTCPPacket(t, 49155, 25, []byte("EHLO offline.example\r\n")),
		goldenUDPPacket(t, 5004, 5004, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 0, 0, 0, 0}),
	}
	for i, data := range packets {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 123), CaptureLength: len(data), Length: len(data)}, data))
	}
	require.NoError(t, f.Close())
	return path
}

func TestOfflineCompactIndexerProtocolOracle(t *testing.T) {
	runOfflineCompactOracle(t, OfflineAnalysisConfig{Inputs: []string{writeCompactProtocolFixture(t)}, VoIP: true, EventCapacity: 64, MaxCalls: 64, SIPConfig: *voip.GetConfig()}, indexOfflineCompactDataset)
}

func TestOfflineCompactIndexerMixedLinkOracle(t *testing.T) {
	paths := append(writeLocatorSIPFixtures(t, "direct"), writeCompactProtocolFixture(t))
	runOfflineCompactOracle(t, OfflineAnalysisConfig{Inputs: paths, VoIP: true, EventCapacity: 32, SIPConfig: *voip.GetConfig()}, indexOfflineCompactDataset)
}

func TestOfflineCompactIndexerBackingOracle(t *testing.T) {
	for _, mode := range []string{"snapshot", "gzip", "empty", "bpf-empty"} {
		t.Run(mode, func(t *testing.T) {
			path := writeCompactProtocolFixture(t)
			cfg := OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 32}
			switch mode {
			case "snapshot":
				cfg.BackingPolicy = "snapshot"
			case "gzip":
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				f, err := os.Create(path + ".gz")
				require.NoError(t, err)
				gz := gzip.NewWriter(f)
				_, err = gz.Write(data)
				require.NoError(t, err)
				require.NoError(t, gz.Close())
				require.NoError(t, f.Close())
				cfg.Inputs = []string{path + ".gz"}
			case "empty":
				require.NoError(t, os.Truncate(path, 24))
			case "bpf-empty":
				cfg.BPFFilter = "host 192.0.2.254"
			}
			runOfflineCompactOracle(t, cfg, indexOfflineCompactDataset)
		})
	}
}

func TestOfflineCompactDetailsFrozenAndOwned(t *testing.T) {
	ctx := context.Background()
	cfg := OfflineAnalysisConfig{Inputs: []string{writeCompactProtocolFixture(t)}, VoIP: true, EventCapacity: 32, SIPConfig: *voip.GetConfig()}
	legacy, err := indexOfflineDataset(ctx, testOfflineStorage(t), 81, cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, legacy.Close()) })
	session, err := indexOfflineCompactDataset(ctx, testOfflineStorage(t), 82, cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })
	before := *voip.GetConfig()
	oldKeylog := viper.Get("tls.keylog_file")
	t.Cleanup(func() { voip.SetConfig(&before); viper.Set("tls.keylog_file", oldKeylog) })
	changed := before
	changed.Security.MaxMessageSize = 1
	voip.SetConfig(&changed)
	viper.Set("tls.keylog_file", "/nonexistent/changed-after-index")
	rng := rand.New(rand.NewSource(3))
	for repeat := 0; repeat < 4; repeat++ {
		for _, id := range rng.Perm(int(session.Dataset.Count())) {
			want, err := legacy.Dataset.Detail(ctx, offline.Token{Dataset: 81}, offline.PacketID(id))
			require.NoError(t, err)
			got, err := session.Dataset.Detail(ctx, offline.Token{Dataset: 82}, offline.PacketID(id))
			require.NoError(t, err)
			require.NoError(t, offlineOracleRecord(want, got))
			require.NoError(t, offlineOracleMetadata(want, got))
			// Caller mutation must neither affect the source nor future cache reads.
			got.Packet.RawData[0] ^= 0xff
			if got.Packet.DNSData != nil {
				got.Packet.DNSData.QueryName = "mutated"
			}
			if got.Packet.TLSData != nil {
				got.Packet.TLSData.SNI = "mutated"
			}
		}
	}
}

func TestOfflineCompactIndexerPrivateOracle(t *testing.T) {
	path := os.Getenv("LIPPYCAT_BENCH_PCAP")
	if path == "" {
		t.Skip("set LIPPYCAT_BENCH_PCAP for private-capture compact parity")
	}
	runOfflineCompactOracle(t, FreezeOfflineOpen([]string{path}, "", 10000).Config, indexOfflineCompactDataset)
}

func TestOfflineCompactIndexerFailureCleanup(t *testing.T) {
	for _, mode := range []string{"cancel", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			path := writeCompactProtocolFixture(t)
			if mode == "truncated" {
				info, err := os.Stat(path)
				require.NoError(t, err)
				require.NoError(t, os.Truncate(path, info.Size()-1))
			}
			storage := testOfflineStorage(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := false
			session, err := indexOfflineCompactDataset(ctx, storage, 91, OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 32}, func(p offline.Progress) {
				ready = ready || p.State == offline.Ready
				if mode == "cancel" && p.State == offline.Finalizing {
					cancel()
				}
			})
			require.Error(t, err)
			if mode == "cancel" {
				require.ErrorIs(t, err, context.Canceled)
			}
			require.Nil(t, session)
			require.False(t, ready)
			require.Zero(t, storage.Resources().DiskBytes)
			require.Zero(t, storage.Resources().InFlightBytes)
		})
	}
}
