//go:build (all || cli || processor || tap) && li

package migrate

import (
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
)

// Journal rewrites always have an explicit source and fresh destination key.
// There is no initialization or implicit format detection in this command.
type liJournalRewriteFlags struct {
	source, destination, sourceFormat, interfaceName string
	sourceKeyFile, sourceKeyID, sourceLegacyKeyID    string
	keyFile, keyID                                   string
	readKeys                                         []string
	maxBytes, maxWorkingBytes                        int64
	inPlace, resume                                  bool
}

func (f *liJournalRewriteFlags) register(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&f.source, "source", "", "Explicit source journal directory")
	flags.StringVar(&f.destination, "destination", "", "Explicit destination journal directory")
	flags.StringVar(&f.sourceFormat, "source-format", "", "Explicit source format: lcx2, per-record or segments")
	flags.StringVar(&f.interfaceName, "interface", "", "Expected source and destination interface: x2 or x3")
	flags.StringVar(&f.sourceKeyFile, "source-key-file", "", "Current active source raw 32-byte encryption key file")
	flags.StringVar(&f.sourceKeyID, "source-key-id", "", "Current active source key ID")
	flags.StringVar(&f.sourceLegacyKeyID, "source-legacy-key-id", "", "Explicit source key ID for the legacy LCX2 format")
	flags.StringArrayVar(&f.readKeys, "read-key", nil, "Prior source read-key reference id=path (at most four)")
	flags.StringVar(&f.keyFile, "key-file", "", "Fresh independent destination raw 32-byte encryption key file")
	flags.StringVar(&f.keyID, "key-id", "", "Fresh destination encryption key ID")
	flags.Int64Var(&f.maxBytes, "max-bytes", 0, "Required destination allocated disk budget, including journal reservations")
	flags.Int64Var(&f.maxWorkingBytes, "max-working-bytes", 1<<30, "Maximum allocated offline rewrite workspace bytes")
	flags.BoolVar(&f.inPlace, "in-place", false, "Explicitly replace the source at the same directory")
	flags.BoolVar(&f.resume, "resume", false, "Resume only the identical authenticated rewrite")
}

func (f *liJournalRewriteFlags) configs() (delivery.JournalConfig, delivery.JournalConfig, error) {
	var expected delivery.PDUType
	switch f.interfaceName {
	case "x2":
		expected = delivery.PDUTypeX2
	case "x3":
		expected = delivery.PDUTypeX3
	default:
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("--interface must explicitly select x2 or x3")
	}
	if f.source == "" || f.destination == "" {
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("--source and --destination are required")
	}
	if f.sourceFormat != "lcx2" && f.sourceFormat != "per-record" && f.sourceFormat != "segments" {
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("--source-format must explicitly select lcx2, per-record or segments")
	}
	if expected == delivery.PDUTypeX3 && f.sourceFormat != "segments" {
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("X3 requires --source-format=segments")
	}
	if f.sourceKeyFile == "" || f.sourceKeyID == "" || f.keyFile == "" || f.keyID == "" {
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("source and destination key IDs and key files are required")
	}
	if f.maxBytes <= 0 || f.maxWorkingBytes <= 0 {
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("--max-bytes and --max-working-bytes must be positive")
	}
	if f.sourceFormat == "lcx2" && f.sourceLegacyKeyID == "" {
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("LCX2 requires explicit --source-legacy-key-id")
	}
	if f.sourceFormat != "lcx2" && f.sourceLegacyKeyID != "" {
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("--source-legacy-key-id applies only to LCX2")
	}
	var prior []securestore.KeyRef
	for _, raw := range f.readKeys {
		ref, err := securestore.ParseReadKey(raw)
		if err != nil {
			return delivery.JournalConfig{}, delivery.JournalConfig{}, fmt.Errorf("source read-key: %w", err)
		}
		prior = append(prior, ref)
	}
	if len(prior) > securestore.MaxPriorKeys {
		return delivery.JournalConfig{}, delivery.JournalConfig{}, errors.New("at most four prior source read keys are supported")
	}
	source := delivery.JournalConfig{Dir: f.source, Interface: expected, KeyFile: f.sourceKeyFile, KeyID: f.sourceKeyID, LegacyKeyID: f.sourceLegacyKeyID, ReadKeys: prior, MaxBytes: f.maxBytes}
	destination := delivery.JournalConfig{Dir: f.destination, Interface: expected, KeyFile: f.keyFile, KeyID: f.keyID, MaxBytes: f.maxBytes}
	return source, destination, nil
}
