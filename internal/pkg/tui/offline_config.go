//go:build tui || all

package tui

import (
	"os"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/viper"
)

// FreezeOfflineOpen captures configuration on the model thread. Workers never
// consult mutable application settings while a replacement is being indexed.
func FreezeOfflineOpen(inputs []string, filter string, capacity int) OpenOfflineDatasetMsg {
	limits := offline.ResourceLimits{Directory: os.TempDir(), DiskBytes: 4 << 30, CacheBytes: 64 << 20, MaxRecordBytes: 8 << 20, MaxSources: 64}
	if viper.IsSet("watch.offline.session_dir") {
		limits.Directory = viper.GetString("watch.offline.session_dir")
	}
	if viper.IsSet("watch.offline.max_disk_bytes") {
		limits.DiskBytes = viper.GetUint64("watch.offline.max_disk_bytes")
	}
	if viper.IsSet("watch.offline.cache_bytes") {
		limits.CacheBytes = viper.GetUint64("watch.offline.cache_bytes")
	}
	if viper.IsSet("watch.offline.max_record_bytes") {
		limits.MaxRecordBytes = viper.GetUint64("watch.offline.max_record_bytes")
	}
	if viper.IsSet("watch.offline.max_sources") {
		limits.MaxSources = viper.GetUint32("watch.offline.max_sources")
	}
	analysis := localCaptureEventOptions(filter)
	analysis.AnalysisProfile = localFileAnalysisProfile(filter)
	analysis.SourceOrdering = append([]string(nil), inputs...)
	cfg := OfflineAnalysisConfig{Inputs: append([]string(nil), inputs...), BPFFilter: filter, VoIP: IsVoIPModeEnabled(), EventCapacity: capacity, Analysis: analysis, SIPConfig: *voip.GetConfig()}
	cfg.ESP = capture.FreezeOfflineESPConfig()
	cfg.MaxCalls = viper.GetInt("watch.max_calls")
	if cfg.MaxCalls <= 0 {
		cfg.MaxCalls = DefaultMaxTrackedCalls
	}
	if viper.GetBool("watch.tls_decryption_enabled") {
		cfg.TLSKeylog = viper.GetString("watch.tls_keylog")
	}
	return OpenOfflineDatasetMsg{Config: cfg, Limits: limits}
}
