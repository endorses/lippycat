//go:build cli || all

package set

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newPolicyStoreCommand() *cobra.Command {
	var node string
	command := &cobra.Command{Use: "policy-store", Short: "Initialize configured encrypted signed-policy storage (offline)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if node != "hunter" && node != "processor" && node != "tap" {
			return fmt.Errorf("--node must be hunter, processor or tap")
		}
		config, err := filterpolicy.FromViper(viper.GetViper(), node)
		if err != nil {
			return err
		}
		if config.Mode != "shared" || config.StorageProtection != "encrypted" {
			return fmt.Errorf("policy-store initialization requires configured shared mode with encrypted storage")
		}
		if err := filterpolicy.Initialize(config); err != nil {
			return err
		}
		cmd.Printf("Initialized encrypted capture policy store for %s\n", node)
		return nil
	}}
	command.Flags().StringVar(&node, "node", "", "Configuration prefix: hunter, processor or tap (required)")
	if err := command.MarkFlagRequired("node"); err != nil {
		panic(err)
	}
	return command
}

func init() { SetCmd.AddCommand(newPolicyStoreCommand()) }
