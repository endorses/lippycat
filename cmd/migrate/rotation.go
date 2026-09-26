//go:build all || cli || processor || tap

package migrate

import (
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
)

const defaultRotationWorkingBytes int64 = 128 << 20

type rotationFlags struct {
	sourceKeyID, sourceKeyFile string
	maxWorkingBytes            int64
}

func (f *rotationFlags) register(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&f.sourceKeyID, "source-key-id", "", "Current active source key ID (encrypted rotation only)")
	flags.StringVar(&f.sourceKeyFile, "source-key-file", "", "Current active source raw key file (encrypted rotation only)")
	flags.Int64Var(&f.maxWorkingBytes, "max-working-bytes", defaultRotationWorkingBytes, "Maximum allocated rotation workspace bytes (encrypted rotation only)")
}

func (f *rotationFlags) validate(cmd *cobra.Command, encrypted bool) error {
	if !encrypted {
		if cmd.Flags().Changed("source-key-id") || cmd.Flags().Changed("source-key-file") || cmd.Flags().Changed("max-working-bytes") {
			return errors.New("--source-key-id, --source-key-file and --max-working-bytes require --source-format=encrypted")
		}
		return nil
	}
	if f.sourceKeyID == "" || f.sourceKeyFile == "" {
		return errors.New("encrypted rotation requires --source-key-id and --source-key-file")
	}
	if f.maxWorkingBytes <= 0 {
		return errors.New("encrypted rotation requires positive --max-working-bytes")
	}
	return nil
}

func (f *rotationFlags) sourceKeys(prior []securestore.KeyRef) securestore.KeyConfig {
	return securestore.KeyConfig{Active: securestore.KeyRef{ID: f.sourceKeyID, File: f.sourceKeyFile}, Prior: prior}
}

// Completion and inventory are distinct from snapshot commitment. Reporting
// failures preserve the actual snapshot outcome, including a committed output
// whose receipt/cleanup still requires resume.
func finishSnapshotRotation(cmd *cobra.Command, label string, result securestore.SnapshotRotationResult, operationErr error) error {
	if operationErr == nil && (result.Outcome != securestore.Committed || !result.Complete || result.ResumeRequired) {
		operationErr = errors.New("rotation did not complete; keep the node stopped and resume the identical operation")
	}
	if result.Outcome == securestore.Committed || result.Outcome == securestore.Uncertain {
		operationErr = errors.Join(operationErr, printSnapshotRotation(cmd, label, result))
	}
	if operationErr == nil {
		return nil
	}
	op := label + " rotation was not committed"
	if result.Outcome == securestore.Uncertain {
		op = label + " rotation commit is uncertain; keep the node stopped and resume the identical operation"
	} else if result.Outcome == securestore.Committed {
		op = label + " rotation committed, but completion, cleanup or reporting failed"
	}
	if result.ResumeRequired && result.Outcome != securestore.Uncertain {
		op += "; keep the node stopped and resume the identical operation"
	}
	return &securestore.CommitError{Outcome: result.Outcome, Op: op, Err: operationErr}
}

func printSnapshotRotation(cmd *cobra.Command, label string, result securestore.SnapshotRotationResult) error {
	state := "committed"
	if result.Outcome == securestore.Uncertain {
		state = "uncertain"
	}
	w := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(w, "Encrypted %s rotation %s.\nComplete: %t; resume required: %t.\nSource active key: %s; output active key: %s.\nAllocated bytes: workspace %d; retained source %d; usage history %d.\nInventory complete: %t. External backups are outside this inventory.\n",
		label, state, result.Complete, result.ResumeRequired, result.SourceKeyID, result.NewKeyID,
		result.WorkingAllocatedBytes, result.OldSourceBytes, result.HistoricalUsageBytes, result.InventoryComplete); err != nil {
		return fmt.Errorf("report rotation result: %w", err)
	}
	for _, artifact := range result.Artifacts {
		if _, err := fmt.Fprintf(w, "Inventory: kind=%s key=%s count=%d allocated_bytes=%d dependency_known=%t\n", artifact.Kind, artifact.KeyID, artifact.Count, artifact.AllocatedBytes, artifact.DependencyKnown); err != nil {
			return fmt.Errorf("report rotation inventory: %w", err)
		}
	}
	return nil
}
