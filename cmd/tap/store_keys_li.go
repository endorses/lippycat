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
		X3: securestore.KeyConfig{Active: securestore.KeyRef{ID: config.LIDeliveryX3SpoolKeyID, File: config.LIDeliveryX3SpoolKeyFile}, Prior: config.LIDeliveryX3SpoolReadKeys},
	})
	if err != nil {
		return err
	}
	config.LIStateFile, config.LIStateKeys = keys.StateFile, keys.State
	config.LIDeliveryX2SpoolKeyID, config.LIDeliveryX2SpoolKeyFile = keys.X2.Active.ID, keys.X2.Active.File
	config.LIDeliveryX2SpoolReadKeys, config.LIDeliveryX2SpoolLegacyKeyID = keys.X2.Prior, keys.X2.LegacyID
	config.LIDeliveryX3SpoolKeyID, config.LIDeliveryX3SpoolKeyFile = keys.X3.Active.ID, keys.X3.Active.File
	config.LIDeliveryX3SpoolReadKeys = keys.X3.Prior
	settings, err := cmdutil.ReadLIX3StoreSettings(flags, viper.GetViper(), "tap", cmdutil.LIX3StoreSettings{
		Dir: config.LIDeliveryX3SpoolDir, MaxBytes: config.LIDeliveryX3SpoolMaxBytes,
		MaxAge: config.LIDeliveryX3MaxAge, ReplayManifest: config.LIDeliveryX3SpoolReplayManifest,
		ExportManifest: config.LIDeliveryX3SpoolExportManifest, ReplayPolicy: config.LIDeliveryX3SpoolReplayPolicy,
	})
	if err != nil {
		return err
	}
	config.LIDeliveryX3SpoolDir, config.LIDeliveryX3SpoolMaxBytes = settings.Dir, settings.MaxBytes
	config.LIDeliveryX3SpoolReplayPolicy = settings.ReplayPolicy
	config.LIDeliveryX3MaxAge = settings.MaxAge
	config.LIDeliveryX3SpoolReplayManifest, config.LIDeliveryX3SpoolExportManifest = settings.ReplayManifest, settings.ExportManifest
	return nil
}
