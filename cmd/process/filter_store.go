//go:build processor || all

package process

import (
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var filterStoreFlags *pflag.FlagSet

func applyProcessFilterStoreConfig(config *processor.Config) error {
	store, err := cmdutil.ReadFilterStoreConfig(filterStoreFlags, viper.GetViper(), "processor", filtering.StoreConfig{
		File: config.FilterFile, Mode: config.FilterStoreMode, Keys: config.FilterStoreKeys,
	})
	if err != nil {
		return err
	}
	config.FilterFile, config.FilterStoreMode, config.FilterStoreKeys = store.File, store.Mode, store.Keys
	return nil
}
