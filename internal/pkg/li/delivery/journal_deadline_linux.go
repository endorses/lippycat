//go:build li && linux

package delivery

import (
	"container/heap"
	"time"
)

type journalDeadline struct {
	at    time.Time
	id    uint64
	index int
}
type journalDeadlines []*journalDeadline

func (h journalDeadlines) Len() int { return len(h) }
func (h journalDeadlines) Less(i, j int) bool {
	if h[i].at.Equal(h[j].at) {
		return h[i].id < h[j].id
	}
	return h[i].at.Before(h[j].at)
}
func (h journalDeadlines) Swap(i, j int) { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *journalDeadlines) Push(x any) {
	v := x.(*journalDeadline)
	v.index = len(*h)
	*h = append(*h, v)
}
func (h *journalDeadlines) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	x.index = -1
	return x
}
func (s *journalSegments) observeDeadline(r JournalRecord) {
	if !r.Deadline.IsZero() {
		if s.deadlineByID == nil {
			s.deadlineByID = map[uint64]*journalDeadline{}
		}
		d := &journalDeadline{at: r.Deadline, id: r.ID}
		s.deadlineByID[r.ID] = d
		heap.Push(&s.deadlines, d)
	}
}
func (s *journalSegments) forgetDeadline(id uint64) {
	if d := s.deadlineByID[id]; d != nil {
		if d.index >= 0 {
			heap.Remove(&s.deadlines, d.index)
		}
		delete(s.deadlineByID, id)
	}
}
func (s *journalSegments) expireDue(now time.Time) error {
	for len(s.deadlines) > 0 && !now.Before(s.deadlines[0].at) {
		controls := make([]journalControl, 0, 2048)
		for len(controls) < 2048 && len(s.deadlines) > 0 && !now.Before(s.deadlines[0].at) {
			d := heap.Pop(&s.deadlines).(*journalDeadline)
			delete(s.deadlineByID, d.id)
			s.j.mu.Lock()
			retained := s.j.entries[d.id] != nil
			s.j.mu.Unlock()
			if retained {
				controls = append(controls, journalControl{Kind: "expired", ID: d.id})
			}
		}
		if len(controls) > 0 {
			if _, err := s.writeControls(controls); err != nil {
				return err
			}
		}
	}
	return nil
}
