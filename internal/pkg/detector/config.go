package detector

import "github.com/spf13/viper"

const (
	DefaultMaxFlows        = 100000
	DefaultMaxCacheEntries = 100000
)

func init() {
	viper.SetDefault("detector.max_flows", DefaultMaxFlows)
	viper.SetDefault("detector.max_cache_entries", DefaultMaxCacheEntries)
}
