//go:build (all || cli || processor || tap) && li

package migrate

import (
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
)

func newLICallCorrelationCommand() *cobra.Command {
	var output, keyFile, keyID string
	var maxRecords int
	cmd := &cobra.Command{
		Use: "li-correlation", Short: "Initialize an encrypted LI call correlation store offline",
		Long: `Initialize an empty authenticated call correlation store while the owning node
is stopped. The output must not exist. Its parent directory must already be
private (0700 or 0750), and the key file must contain exactly 32 private raw bytes.
Use dedicated fresh key material, independent of administrative state and journals.

This command never activates tasks or sends interception product. It does not
replace existing stores, reset encryption usage, or edit runtime configuration.
After an uncertain result, keep the node stopped and reconcile the store and its
usage history; do not remove the ledger or blindly reinitialize with the same key.
Use the rotate subcommand for an existing authenticated store.`,
		Example: `  lc migrate li-correlation --output /var/lib/lippycat/li-correlation.enc \
    --key-file /etc/lippycat/keys/li-correlation.key --key-id correlation-1 \
    --max-records 100000`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				return errors.New("--output is required")
			}
			if keyFile == "" || keyID == "" {
				return errors.New("--key-file and --key-id are required")
			}
			if err := validateLICorrelationRecordLimit(maxRecords); err != nil {
				return err
			}
			keys := securestore.KeyConfig{Active: securestore.KeyRef{ID: keyID, File: keyFile}}
			outcome, err := li.InitializeCallCorrelationStore(output, keys, maxRecords)
			if err == nil && outcome != securestore.Committed {
				err = errors.New("the operation did not establish a committed snapshot")
			}
			if err != nil {
				return liCorrelationStoreError(outcome, err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Encrypted LI call correlation store committed."); err != nil {
				return liCorrelationStoreError(securestore.Committed, fmt.Errorf("report initialization result: %w", err))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "New snapshot path (required; must not exist)")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "Dedicated active raw 32-byte encryption key file")
	cmd.Flags().StringVar(&keyID, "key-id", "", "Active encryption key ID")
	cmd.Flags().IntVar(&maxRecords, "max-records", li.DefaultCallCorrelationConfig().MaxRecords, "Maximum retained decisions (1 to 1000000)")
	cmd.AddCommand(newLICallCorrelationRotateCommand())
	return cmd
}

func newLICallCorrelationRotateCommand() *cobra.Command {
	var source, destination, keyFile, keyID string
	var readKeys []string
	var inPlace, resume bool
	var maxRecords int
	var rotation rotationFlags
	cmd := &cobra.Command{
		Use: "rotate", Short: "Rotate an encrypted LI call correlation store offline",
		Long: `Rotate an authenticated call correlation snapshot to a fresh independent key
while its owning node is stopped. --source-key-id, --source-key-file and optional
--read-key references belong to the source. --key-id and --key-file select the
fresh output key. Key files contain exactly 32 private raw bytes.

Source and destination must share the same private directory. Changed-path
rotation retains the source; same-path replacement requires --in-place. The
rotation preserves the exact retained decisions and usage history. --resume
accepts only the original authenticated operation, paths, source content and keys.
Keep the node stopped after uncertainty and resume the identical operation.

Working space is bounded by --max-working-bytes. Output reports retained old-key
objects and usage history; external backups require a separate inventory. This
command does not edit runtime configuration, authorize calls, deliver product,
or declare previous keys safe to retire.`,
		Example: `  lc migrate li-correlation rotate \
    --source /var/lib/lippycat/li-correlation.enc --destination /var/lib/lippycat/li-correlation-new.enc \
    --source-key-id correlation-1 --source-key-file /etc/lippycat/keys/li-correlation.key \
    --key-id correlation-2 --key-file /etc/lippycat/keys/li-correlation-new.key`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if source == "" || destination == "" {
				return errors.New("rotation requires --source and --destination")
			}
			if keyFile == "" || keyID == "" {
				return errors.New("--key-file and --key-id are required")
			}
			if err := rotation.validate(cmd, true); err != nil {
				return err
			}
			if err := validateLICorrelationRecordLimit(maxRecords); err != nil {
				return err
			}
			var prior []securestore.KeyRef
			for _, value := range readKeys {
				key, err := securestore.ParseReadKey(value)
				if err != nil {
					return err
				}
				prior = append(prior, key)
			}
			keys := securestore.KeyConfig{Active: securestore.KeyRef{ID: keyID, File: keyFile}}
			result, err := li.RotateCallCorrelationStore(source, destination, rotation.sourceKeys(prior), keys, maxRecords, li.StateRotationOptions{
				InPlace: inPlace, Resume: resume, MaxWorkingBytes: rotation.maxWorkingBytes,
			})
			return finishSnapshotRotation(cmd, "LI call correlation store", result, err)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&source, "source", "", "Existing authenticated source snapshot path")
	flags.StringVar(&destination, "destination", "", "Explicit output snapshot path")
	flags.StringVar(&keyFile, "key-file", "", "Fresh active output raw 32-byte encryption key file")
	flags.StringVar(&keyID, "key-id", "", "Fresh active output encryption key ID")
	flags.StringArrayVar(&readKeys, "read-key", nil, "Prior source read-key reference id=path (at most four)")
	flags.IntVar(&maxRecords, "max-records", li.DefaultCallCorrelationConfig().MaxRecords, "Maximum retained decisions (1 to 1000000)")
	flags.BoolVar(&inPlace, "in-place", false, "Explicitly replace the source at the same path")
	flags.BoolVar(&resume, "resume", false, "Resume the identical authenticated rotation")
	rotation.register(cmd)
	return cmd
}

func validateLICorrelationRecordLimit(limit int) error {
	if limit < 1 || limit > 1000000 {
		return errors.New("--max-records must be between 1 and 1000000")
	}
	return nil
}

func liCorrelationStoreError(outcome securestore.Outcome, err error) error {
	op := "LI call correlation store was not committed"
	if outcome == securestore.Uncertain {
		op = "LI call correlation store commit is uncertain; keep the node stopped and reconcile the existing store and usage history"
	} else if outcome == securestore.Committed {
		op = "LI call correlation store committed, but cleanup or reporting failed"
	}
	return &securestore.CommitError{Outcome: outcome, Op: op, Err: err}
}
