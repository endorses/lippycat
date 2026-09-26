//go:build (all || cli || processor || tap) && li

package migrate

import (
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
)

func addLICommands(cmd *cobra.Command) { cmd.AddCommand(newLIStateCommand()) }

func newLIStateCommand() *cobra.Command {
	var source, destination, sourceFormat, keyFile, keyID, radiusStateFile string
	var readKeys []string
	var initialize, inPlace, resume bool
	cmd := &cobra.Command{
		Use: "li-state", Short: "Initialize or encrypt a LI administrative state store offline",
		Long: `Initialize an empty encrypted LI state store, or migrate an explicitly selected
JSON source. Stop the owning node first. The destination directory must already
be private (0700 or 0750), and key files must contain exactly 32 raw private bytes.

Changed-path migration retains the source. Same-path conversion requires
--in-place. --resume accepts only the original authenticated operation, source
content, destination and active key; it never resets encryption usage.

Migration pins the RADIUS allocator at SOURCE.radius-correlation. Empty init
pins DESTINATION.radius-correlation. Use --radius-state-file if the existing
allocator used a custom path. The allocator is neither moved nor rewritten.
This command never activates tasks or sends interception product.`,
		Example: `  lc migrate li-state --init --destination /var/lib/lippycat/state.enc --key-id state-1 --key-file /etc/lippycat/state.key
  lc migrate li-state --source-format json --source /var/lib/lippycat/state.json --destination /var/lib/lippycat/state.enc --key-id state-1 --key-file /etc/lippycat/state.key`,
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
			} else if source == "" || sourceFormat != "json" {
				return errors.New("migration requires --source and explicit --source-format=json; use --init for an empty store")
			}
			keys := securestore.KeyConfig{Active: securestore.KeyRef{ID: keyID, File: keyFile}}
			for _, raw := range readKeys {
				ref, err := securestore.ParseReadKey(raw)
				if err != nil {
					return err
				}
				keys.Prior = append(keys.Prior, ref)
			}
			options := li.StateOfflineOptions{InPlace: inPlace, Resume: resume, RADIUSStateFile: radiusStateFile}
			var outcome securestore.Outcome
			var err error
			if initialize {
				outcome, err = li.InitializeEncryptedStateStore(destination, keys, options)
			} else {
				outcome, err = li.MigrateJSONStateStore(source, destination, keys, options)
			}
			if err != nil {
				return liStateStoreError(outcome, err)
			}
			if outcome != securestore.Committed {
				return liStateStoreError(outcome, errors.New("the operation did not establish a committed snapshot"))
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Encrypted LI state store committed."); err != nil {
				return liStateStoreError(securestore.Committed, fmt.Errorf("report migration result: %w", err))
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&source, "source", "", "Explicit source snapshot path")
	flags.StringVar(&destination, "destination", "", "Explicit destination snapshot path (required)")
	flags.StringVar(&sourceFormat, "source-format", "", "Explicit source format: json")
	flags.BoolVar(&initialize, "init", false, "Initialize an empty encrypted store without a source")
	flags.BoolVar(&inPlace, "in-place", false, "Explicitly replace the source at the same path")
	flags.BoolVar(&resume, "resume", false, "Resume the identical authenticated initialization or migration")
	flags.StringVar(&radiusStateFile, "radius-state-file", "", "Existing RADIUS allocator path override (default: source or initial destination plus .radius-correlation)")
	flags.StringVar(&keyFile, "key-file", "", "Active raw 32-byte encryption key file")
	flags.StringVar(&keyID, "key-id", "", "Active encryption key ID")
	flags.StringArrayVar(&readKeys, "read-key", nil, "Prior read-key reference id=path (repeatable, at most four)")
	return cmd
}

func liStateStoreError(outcome securestore.Outcome, err error) error {
	op := "LI state store was not committed"
	if outcome == securestore.Uncertain {
		op = "LI state store commit is uncertain; keep the node stopped and resume the identical operation"
	} else if outcome == securestore.Committed {
		op = "LI state store committed, but cleanup or reporting failed"
	}
	return &securestore.CommitError{Outcome: outcome, Op: op, Err: err}
}
