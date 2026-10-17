//go:build cli || all

package set

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/endorses/lippycat/internal/pkg/packetspool"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
)

// Initialization is deliberately separate from runtime Open: deleting a state
// file must never silently create a fresh capture identity or deduplication store.
func newPacketStoreCommand(receiver bool) *cobra.Command {
	var directory, source, destination, scope, protection, keyID, keyFile, policy string
	var readKeys []string
	var maxBytes, maxRecordBytes uint64
	var maxRecords, maxSessions, maxLossRanges int
	var maxAge time.Duration
	name, short := "packet-spool", "Initialize a private hunter raw packet spool (offline)"
	if receiver {
		name, short = "packet-custody", "Initialize a private processor raw custody store (offline)"
	}
	command := &cobra.Command{Use: name, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		keys := securestore.KeyConfig{Active: securestore.KeyRef{ID: keyID, File: keyFile}}
		for _, value := range readKeys {
			ref, err := securestore.ParseReadKey(value)
			if err != nil {
				return err
			}
			keys.Prior = append(keys.Prior, ref)
		}
		if receiver {
			config := packetreceipt.StoreConfig{Directory: directory, DestinationID: destination, Protection: protection, MaxBytes: int64(maxBytes), MaxRecordBytes: int(maxRecordBytes), MaxSessions: maxSessions, MaxRecords: maxRecords, MaxLossRanges: maxLossRanges, Keys: keys}
			if maxBytes > 64<<20 || maxRecordBytes > 32<<20 {
				return fmt.Errorf("custody snapshot/record bounds exceed supported limits")
			}
			if err := packetreceipt.Initialize(config); err != nil {
				return err
			}
		} else {
			var ring *securestore.Keyring
			if protection == packetspool.Encrypted {
				var err error
				ring, err = securestore.LoadKeyring(keys)
				if err != nil {
					return err
				}
			} else if keyID != "" || keyFile != "" || len(readKeys) > 0 {
				return fmt.Errorf("private protection forbids encryption keys")
			}
			if err := packetspool.Initialize(packetspool.Config{Directory: directory, SourceID: source, DestinationID: destination, AckScope: scope, Protection: protection, Keys: ring, MaxBytes: maxBytes, MaxRecordBytes: maxRecordBytes, MaxRecords: maxRecords, MaxLossRanges: maxLossRanges, MaxAge: maxAge, Policy: packetspool.ExhaustionPolicy(policy)}); err != nil {
				return err
			}
		}
		cmd.Printf("Initialized %s in %s\n", name, directory)
		return nil
	}}
	flags := command.Flags()
	flags.StringVar(&directory, "dir", "", "Private store directory (required)")
	flags.StringVar(&destination, "destination-id", "", "Logical receipt destination (required)")
	flags.StringVar(&protection, "protection", "", "Explicit at-rest protection: private or encrypted (required)")
	flags.StringVar(&keyID, "key-id", "", "Active encryption key ID")
	flags.StringVar(&keyFile, "key-file", "", "Private file containing the 32-byte encryption key")
	flags.StringArrayVar(&readKeys, "read-key", nil, "Prior encryption read key, id=path (repeatable)")
	flags.Uint64Var(&maxBytes, "max-bytes", 32<<20, "Configured store byte bound")
	flags.Uint64Var(&maxRecordBytes, "max-record-bytes", 4<<20, "Maximum encoded raw batch bytes")
	flags.IntVar(&maxRecords, "max-records", 4096, "Maximum retained record metadata entries")
	flags.IntVar(&maxLossRanges, "max-loss-ranges", 4096, "Maximum retained loss ranges")
	if receiver {
		flags.IntVar(&maxSessions, "max-sessions", 256, "Maximum retained producer sessions, including retired tombstones")
	} else {
		flags.StringVar(&source, "source-id", "", "Stable capture source ID (required)")
		flags.StringVar(&scope, "ack-scope", "receiver", "Receipt scope: receiver or central")
		flags.StringVar(&policy, "exhaustion-policy", "drop_oldest", "Retention policy: drop_oldest or drop_new")
		flags.DurationVar(&maxAge, "max-age", 0, "Maximum retained batch age (0 disables age eviction)")
	}
	for _, required := range []string{"dir", "destination-id", "protection"} {
		if err := command.MarkFlagRequired(required); err != nil {
			panic(err)
		}
	}
	if !receiver {
		if err := command.MarkFlagRequired("source-id"); err != nil {
			panic(err)
		}
	}
	return command
}

func init() { SetCmd.AddCommand(newPacketStoreCommand(false), newPacketStoreCommand(true)) }
