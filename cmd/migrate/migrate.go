//go:build all || cli || processor || tap

package migrate

import (
	"errors"
	"fmt"

	store "github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
)

var MigrateCmd = NewCommand()

// NewCommand returns independent command state for offline storage operations.
// It starts no processor, capture engine, policy manager, or network listener.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "migrate", Short: "Initialize and migrate offline stores",
		Long: "Initialize and migrate persisted stores while their owning nodes are stopped.",
	}
	cmd.AddCommand(newFilterStoreCommand())
	return cmd
}

func newFilterStoreCommand() *cobra.Command {
	var source, destination, sourceFormat, keyFile, keyID string
	var readKeys []string
	var initialize, inPlace, resume bool
	cmd := &cobra.Command{
		Use: "filter-store", Short: "Initialize or encrypt a managed filter store offline",
		Long: `Initialize an empty encrypted filter store, or migrate an explicitly selected
YAML source. Stop the owning node first. The destination directory must already
be private (0700 or 0750), and key files must contain exactly 32 raw private bytes.

Changed-path migration retains the source. Same-path conversion requires
--in-place. --resume accepts only the original authenticated operation, source
content, destination and active key; it never resets encryption usage.`,
		Example: `  lc migrate filter-store --init --destination /var/lib/lippycat/filters.enc --key-id filters-1 --key-file /etc/lippycat/filters.key
  lc migrate filter-store --source-format yaml --source /var/lib/lippycat/filters.yaml --destination /var/lib/lippycat/filters.enc --key-id filters-1 --key-file /etc/lippycat/filters.key`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if destination == "" {
				return errors.New("--destination is required")
			}
			if keyFile == "" || keyID == "" {
				return errors.New("--key-file and --key-id are required")
			}
			if initialize {
				if source != "" || sourceFormat != "" || inPlace {
					return errors.New("--init cannot be combined with --source, --source-format, or --in-place")
				}
			} else if source == "" || sourceFormat != "yaml" {
				return errors.New("migration requires --source and explicit --source-format=yaml; use --init for an empty store")
			}
			keys := securestore.KeyConfig{Active: securestore.KeyRef{ID: keyID, File: keyFile}}
			for _, raw := range readKeys {
				ref, err := securestore.ParseReadKey(raw)
				if err != nil {
					return err
				}
				keys.Prior = append(keys.Prior, ref)
			}
			options := store.OfflineOptions{InPlace: inPlace, Resume: resume}
			var outcome securestore.Outcome
			var err error
			if initialize {
				outcome, err = store.InitializeEncryptedFilterStore(destination, keys, options)
			} else {
				outcome, err = store.MigrateYAMLFilterStore(source, destination, keys, options)
			}
			if err != nil {
				return filterStoreError(outcome, err)
			}
			if outcome != securestore.Committed {
				return filterStoreError(outcome, errors.New("the operation did not establish a committed snapshot"))
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Encrypted filter store committed."); err != nil {
				return filterStoreError(securestore.Committed, fmt.Errorf("report migration result: %w", err))
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&source, "source", "", "Explicit source snapshot path")
	flags.StringVar(&destination, "destination", "", "Explicit destination snapshot path (required)")
	flags.StringVar(&sourceFormat, "source-format", "", "Explicit source format: yaml")
	flags.BoolVar(&initialize, "init", false, "Initialize an empty encrypted store without a source")
	flags.BoolVar(&inPlace, "in-place", false, "Explicitly replace the source at the same path")
	flags.BoolVar(&resume, "resume", false, "Resume the identical authenticated initialization or migration")
	flags.StringVar(&keyFile, "key-file", "", "Active raw 32-byte encryption key file")
	flags.StringVar(&keyID, "key-id", "", "Active encryption key ID")
	flags.StringArrayVar(&readKeys, "read-key", nil, "Prior read-key reference id=path (repeatable, at most four)")
	return cmd
}

func filterStoreError(outcome securestore.Outcome, err error) error {
	op := "filter store was not committed"
	if outcome == securestore.Uncertain {
		op = "filter store commit is uncertain; keep the node stopped and resume the identical operation"
	} else if outcome == securestore.Committed {
		op = "filter store committed, but cleanup or reporting failed"
	}
	return &securestore.CommitError{Outcome: outcome, Op: op, Err: err}
}
