//go:build li && !linux

package delivery

import "errors"

func rewriteJournal(source, destination JournalConfig, options JournalRewriteOptions) (JournalRewriteResult, error) {
	return JournalRewriteResult{}, errors.New("offline journal rewrite requires Linux allocated workspace support")
}
