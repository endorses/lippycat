package packetreceipt

import (
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"time"
)

func (s *Store) Keyring() *securestore.Keyring { return s.keys }

type Stats struct {
	PendingRecords, HistoryRecords, Sessions int
	PendingBytes                             uint64
	OldestAge                                time.Duration
}

func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := Stats{Sessions: len(s.state.Sessions)}
	var oldest int64
	for _, session := range s.state.Sessions {
		for _, record := range session.Records {
			stats.HistoryRecords++
			if !record.Processed {
				stats.PendingRecords++
				stats.PendingBytes += uint64(len(record.Payload))
				if oldest == 0 || record.AcceptedNS < oldest {
					oldest = record.AcceptedNS
				}
			}
		}
	}
	if oldest > 0 {
		stats.OldestAge = max(time.Duration(0), time.Since(time.Unix(0, oldest)))
	}
	return stats
}
