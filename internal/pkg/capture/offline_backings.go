package capture

import (
	"context"
	"github.com/endorses/lippycat/internal/pkg/offline"
)

type offlineBackingsKey struct{}
type offlineBackingsConfig struct {
	registry *offline.BackingRegistry
	policy   offline.BackingPolicy
}

// WithOfflineBackings enables locator emission for internal migration consumers.
// The caller owns the registry and must retain it through all packet readers.
// Cursor EOF/Close never closes registry-owned inputs. This does not select a
// new production dataset backend.
func WithOfflineBackings(ctx context.Context, registry *offline.BackingRegistry, policy offline.BackingPolicy) context.Context {
	return context.WithValue(ctx, offlineBackingsKey{}, offlineBackingsConfig{registry, policy})
}

// WithOfflineBackingPolicy freezes the session policy without enabling the
// internal locator path when no registry was supplied.
func WithOfflineBackingPolicy(ctx context.Context, policy offline.BackingPolicy) context.Context {
	cfg, _ := ctx.Value(offlineBackingsKey{}).(offlineBackingsConfig)
	cfg.policy = policy
	return context.WithValue(ctx, offlineBackingsKey{}, cfg)
}
