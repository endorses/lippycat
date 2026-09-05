package capture

import (
	"context"

	"github.com/spf13/viper"
)

// OfflineESPConfig freezes the optional ESP normalization policy for a session.
type OfflineESPConfig struct {
	Enabled  bool
	Explicit bool
	ICVSize  int
}

type offlineESPContextKey struct{}

// FreezeOfflineESPConfig reads configuration once on the caller's settings thread.
func FreezeOfflineESPConfig() OfflineESPConfig {
	cfg := OfflineESPConfig{Explicit: viper.GetBool("esp_null"), ICVSize: -1}
	cfg.Enabled = cfg.Explicit || viper.GetBool("esp_heuristic")
	if viper.IsSet("esp_icv_size") {
		cfg.ICVSize = viper.GetInt("esp_icv_size")
	}
	switch cfg.ICVSize {
	case -1, 0, 8, 12, 16:
	default:
		cfg.ICVSize = -1
	}
	return cfg
}

// WithOfflineESPConfig gives all ordered source cursors the same immutable policy.
func WithOfflineESPConfig(ctx context.Context, cfg OfflineESPConfig) context.Context {
	return context.WithValue(ctx, offlineESPContextKey{}, cfg)
}

func offlineESPConfigFromContext(ctx context.Context) OfflineESPConfig {
	if cfg, ok := ctx.Value(offlineESPContextKey{}).(OfflineESPConfig); ok {
		return cfg
	}
	explicit, icv := getESPNullConfig()
	return OfflineESPConfig{Enabled: explicit || espHeuristicOn, Explicit: explicit, ICVSize: icv}
}
