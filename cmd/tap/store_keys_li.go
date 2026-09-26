//go:build (tap || all) && li

package tap

import (
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var liStoreKeyFlags *pflag.FlagSet

func registerLIStoreKeyFlags(cmd *cobra.Command) {
	liStoreKeyFlags = cmd.PersistentFlags()
	if err := cmdutil.RegisterLIStoreKeyFlags(liStoreKeyFlags, viper.GetViper(), "tap"); err != nil {
		panic(err) // Static flag registration errors are programming errors.
	}
}

func applyLIStoreKeyConfig(cmd *cobra.Command, config *processor.Config) error {
	flags := liStoreKeyFlags
	if cmd != nil {
		flags = cmd.PersistentFlags()
	}
	keys, err := cmdutil.ReadLIStoreKeys(flags, viper.GetViper(), "tap", cmdutil.LIStoreKeys{
		StateFile: config.LIStateFile, State: config.LIStateKeys,
		X2: securestore.KeyConfig{Active: securestore.KeyRef{ID: config.LIDeliveryX2SpoolKeyID, File: config.LIDeliveryX2SpoolKeyFile}, Prior: config.LIDeliveryX2SpoolReadKeys, LegacyID: config.LIDeliveryX2SpoolLegacyKeyID},
	})
	if err != nil {
		return err
	}
	config.LIStateFile, config.LIStateKeys = keys.StateFile, keys.State
	config.LIDeliveryX2SpoolKeyID, config.LIDeliveryX2SpoolKeyFile = keys.X2.Active.ID, keys.X2.Active.File
	config.LIDeliveryX2SpoolReadKeys, config.LIDeliveryX2SpoolLegacyKeyID = keys.X2.Prior, keys.X2.LegacyID
	return nil
}
