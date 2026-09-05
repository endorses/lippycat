package offline

import (
	"maps"
	"strings"
)

const protocolCardinalityLimit = 1000
const addressCardinalityLimit = 10000

// statisticsAccumulator counts accepted records exactly, with bounded address
// and protocol cardinality. Counters retain the first distinct keys observed;
// frequencies for those keys stay exact even after the cap is reached.
type statisticsAccumulator struct {
	stats     Statistics
	truncated [3]bool
	keyBytes  [3]uint64
}

func newStatisticsAccumulator() *statisticsAccumulator {
	return &statisticsAccumulator{stats: Statistics{Protocols: make(map[string]uint64), SourceCounts: make(map[string]uint64), DestinationCounts: make(map[string]uint64)}}
}

func (a *statisticsAccumulator) Add(s Summary) {
	p := s.packet
	n := uint64(max(p.Length, 0))
	if a.stats.Packets == 0 {
		a.stats.First, a.stats.Last = p.Timestamp, p.Timestamp
		a.stats.MinPacketSize = n
	}
	a.stats.Packets++
	a.stats.Bytes += n
	if p.Timestamp.Before(a.stats.First) {
		a.stats.First = p.Timestamp
	}
	if p.Timestamp.After(a.stats.Last) {
		a.stats.Last = p.Timestamp
	}
	a.stats.MinPacketSize = min(a.stats.MinPacketSize, n)
	a.stats.MaxPacketSize = max(a.stats.MaxPacketSize, n)
	a.add(a.stats.Protocols, p.Protocol, protocolCardinalityLimit, 0)
	a.add(a.stats.SourceCounts, p.SrcIP, addressCardinalityLimit, 1)
	a.add(a.stats.DestinationCounts, p.DstIP, addressCardinalityLimit, 2)
}

func (a *statisticsAccumulator) add(m map[string]uint64, key string, limit, index int) {
	if _, ok := m[key]; ok {
		m[key]++
		return
	}
	// Bound string retention independently of cardinality: malformed addresses
	// and arbitrary protocol names must not retain record-sized keys.
	if len(m) < limit && uint64(len(key)) <= 1<<20-a.keyBytes[index] {
		m[strings.Clone(key)]++
		a.keyBytes[index] += uint64(len(key))
		return
	}
	a.truncated[index] = true
}

func (a *statisticsAccumulator) Snapshot() Statistics {
	s := cloneStatistics(a.stats)
	s.Sources, s.Destinations = uint64(len(s.SourceCounts)), uint64(len(s.DestinationCounts))
	for i, name := range [...]string{"protocols", "sources", "destinations"} {
		if a.truncated[i] {
			s.TruncatedCardinality = append(s.TruncatedCardinality, name)
		}
	}
	return s
}

func cloneStatistics(s Statistics) Statistics {
	s.Protocols = maps.Clone(s.Protocols)
	s.SourceCounts = maps.Clone(s.SourceCounts)
	s.DestinationCounts = maps.Clone(s.DestinationCounts)
	s.TruncatedCardinality = append([]string(nil), s.TruncatedCardinality...)
	return s
}
