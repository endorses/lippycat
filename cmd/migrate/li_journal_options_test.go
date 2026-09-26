//go:build (all || cli || processor || tap) && li

package migrate

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestLIJournalRewriteOptionsKeepSourceAndDestinationKeysSeparate(t *testing.T) {
	var options liJournalRewriteFlags
	cmd := &cobra.Command{}
	options.register(cmd)
	require.NoError(t, cmd.ParseFlags([]string{
		"--source=/private/source", "--destination=/private/output", "--interface=x3", "--source-format=segments",
		"--source-key-id=source-v2", "--source-key-file=/keys/source-v2", "--read-key=source-v1=/keys/source-v1",
		"--key-id=output-v3", "--key-file=/keys/output-v3", "--max-bytes=1073741824", "--max-working-bytes=536870912", "--resume",
	}))
	source, destination, err := options.configs()
	require.NoError(t, err)
	require.Equal(t, delivery.PDUTypeX3, source.Interface)
	require.Equal(t, delivery.PDUTypeX3, destination.Interface)
	require.Equal(t, "source-v2", source.KeyID)
	require.Equal(t, []securestore.KeyRef{{ID: "source-v1", File: "/keys/source-v1"}}, source.ReadKeys)
	require.Equal(t, "output-v3", destination.KeyID)
	require.Empty(t, destination.ReadKeys)
	require.True(t, options.resume)
	require.EqualValues(t, 512<<20, options.maxWorkingBytes)
}

func TestLIJournalRewriteRejectsAmbiguousOptionsBeforeKeyReads(t *testing.T) {
	base := liJournalRewriteFlags{source: "absent-source", destination: "absent-output", sourceFormat: "segments", interfaceName: "x3", sourceKeyFile: "absent-source-key", sourceKeyID: "source", keyFile: "absent-output-key", keyID: "output", maxBytes: 1 << 30, maxWorkingBytes: 1 << 30}
	for name, alter := range map[string]func(*liJournalRewriteFlags){
		"missing-interface":            func(f *liJournalRewriteFlags) { f.interfaceName = "" },
		"unknown-interface":            func(f *liJournalRewriteFlags) { f.interfaceName = "x4" },
		"missing-format":               func(f *liJournalRewriteFlags) { f.sourceFormat = "" },
		"unknown-format":               func(f *liJournalRewriteFlags) { f.sourceFormat = "auto" },
		"legacy-x3":                    func(f *liJournalRewriteFlags) { f.sourceFormat = "lcx2" },
		"legacy-missing-key-selection": func(f *liJournalRewriteFlags) { f.interfaceName, f.sourceFormat = "x2", "lcx2" },
		"irrelevant-legacy-key":        func(f *liJournalRewriteFlags) { f.sourceLegacyKeyID = "source" },
		"missing-source":               func(f *liJournalRewriteFlags) { f.source = "" },
		"missing-output":               func(f *liJournalRewriteFlags) { f.destination = "" },
		"missing-output-key":           func(f *liJournalRewriteFlags) { f.keyFile = "" },
		"missing-source-key":           func(f *liJournalRewriteFlags) { f.sourceKeyID = "" },
		"zero-capacity":                func(f *liJournalRewriteFlags) { f.maxBytes = 0 },
		"negative-workspace":           func(f *liJournalRewriteFlags) { f.maxWorkingBytes = -1 },
		"malformed-read-key":           func(f *liJournalRewriteFlags) { f.readKeys = []string{"sensitive-malformed-reference"} },
		"too-many-read-keys":           func(f *liJournalRewriteFlags) { f.readKeys = []string{"a=/a", "b=/b", "c=/c", "d=/d", "e=/e"} },
	} {
		t.Run(name, func(t *testing.T) {
			options := base
			alter(&options)
			_, _, err := options.configs()
			require.Error(t, err)
			require.NotContains(t, err.Error(), "sensitive-malformed-reference")
		})
	}
}

func TestLIJournalCommandRegistrationAndPreflight(t *testing.T) {
	for _, args := range [][]string{
		{"li-journal"},
		{"li-journal", "--interface=x3"},
		{"li-journal", "unexpected-positional"},
		{"li-journal", "--interface=x3", "--source-format=lcx2", "--source=absent", "--destination=absent-output"},
	} {
		cmd := NewCommand()
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		command, _, err := cmd.Find([]string{"li-journal"})
		require.NoError(t, err)
		require.Equal(t, "li-journal", command.Name())
		cmd.SetArgs(args)
		require.Error(t, cmd.Execute(), "explicit selection and keys must precede backend effects")
	}
}
