//go:build tui || all

package tui

import (
	"context"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
)

// The legacy builder remains an explicit test oracle after production cutover.
func indexOfflineLegacyDataset(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
	return indexOfflineDatasetBackend(ctx, storage, generation, cfg, report, nil, false, false)
}
func indexOfflineCompactDataset(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
	return indexOfflineDatasetBackend(ctx, storage, generation, cfg, report, nil, true, true)
}
func indexOfflineDatasetObserved(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), observe func(string, time.Duration)) (*offlineIndexedSession, error) {
	return indexOfflineDatasetBackend(ctx, storage, generation, cfg, report, observe, false, false)
}
func indexOfflineLocatorObserved(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), observe func(string, time.Duration)) (*offlineIndexedSession, error) {
	return indexOfflineDatasetBackend(ctx, storage, generation, cfg, report, observe, true, false)
}
