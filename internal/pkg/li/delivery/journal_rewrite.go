//go:build li

package delivery

import "github.com/endorses/lippycat/internal/pkg/securestore"

// JournalRewriteOptions declares an offline source format and explicit output
// publication policy. Rewrite never starts replay, authorization or networking.
type JournalRewriteOptions struct {
	SourceFormat    string
	InPlace, Resume bool
	MaxWorkingBytes int64
}
type JournalRewriteResult = securestore.SnapshotRotationResult

func RewriteJournal(source, destination JournalConfig, options JournalRewriteOptions) (JournalRewriteResult, error) {
	return rewriteJournal(source, destination, options)
}
