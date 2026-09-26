//go:build li && !linux

package delivery

import "errors"

func openSegmentJournal(JournalConfig, bool) (*Journal, error) {
	return nil, errors.New("fixed-segment journal requires Linux private preallocation and atomic publication")
}
