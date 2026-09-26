//go:build (all || cli || processor || tap) && li

package migrate

import (
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/spf13/cobra"
)

func newLIJournalCommand() *cobra.Command {
	var options liJournalRewriteFlags
	cmd := &cobra.Command{
		Use: "li-journal", Short: "Migrate or rotate an encrypted LI journal offline",
		Long: `Rewrite an explicitly selected X2 or X3 journal with a fresh independent key
while the owning node is stopped. Select both --interface and --source-format;
there is no automatic format detection or empty-store initialization.

Source keys belong to --source-key-id, --source-key-file and --read-key. LCX2
additionally requires --source-legacy-key-id. --key-id and --key-file select the
fresh destination key. Key files contain exactly 32 private raw bytes. Both
journals and their parent directories must satisfy private ownership checks.

The rewrite preserves journal identity, original product bytes and sequence
numbers, absolute deadlines, call and revocation controls, and allocation
highwaters. A legacy source whose deleted-record highwater cannot be established
is rejected instead of risking identifier reuse. This command never authorizes
or sends interception product.

Changed-path output must not clobber existing data. Same-path replacement requires
--in-place. --resume accepts only the original authenticated operation and keys.
Keep the owning node stopped after an uncertain result and resume that operation.
Working space is finite and charged before publication; insufficient capacity
fails rather than silently reducing retention. Output includes retained old-key
objects and usage history; external backups require a separate key inventory.
The command does not edit runtime configuration or declare keys safe to retire.`,
		Example: `  lc migrate li-journal --interface x3 --source-format segments \
    --source /var/lib/lippycat/x3 --destination /var/lib/lippycat/x3-new \
    --source-key-id x3-v1 --source-key-file /etc/lippycat/x3-v1.key \
    --key-id x3-v2 --key-file /etc/lippycat/x3-v2.key --max-bytes 4294967296`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			source, destination, err := options.configs()
			if err != nil {
				return err
			}
			result, err := delivery.RewriteJournal(source, destination, delivery.JournalRewriteOptions{
				SourceFormat: options.sourceFormat, InPlace: options.inPlace,
				Resume: options.resume, MaxWorkingBytes: options.maxWorkingBytes,
			})
			return finishSnapshotRotation(cmd, "LI journal", result, err)
		},
	}
	options.register(cmd)
	return cmd
}
