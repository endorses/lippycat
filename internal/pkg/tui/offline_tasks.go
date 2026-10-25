//go:build tui || all

package tui

import "sync"

// One session owns these operation slots across revision publication. Export
// pins keep their original query alive; publication never cancels them.
type offlineTaskOwner struct {
	mu        sync.Mutex
	export    *offlineExportState
	markRange *offlineMarkRangeState
	closed    bool
}

func (o *offlineTaskOwner) Cancel() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.export != nil {
		o.export.cancel()
	}
	if o.markRange != nil {
		o.markRange.cancel()
	}
}
func (o *offlineTaskOwner) Close() error {
	o.mu.Lock()
	o.closed = true
	export, marks := o.export, o.markRange
	if export != nil {
		export.cancel()
	}
	if marks != nil {
		marks.cancel()
	}
	o.mu.Unlock()
	if export != nil {
		<-export.done
	}
	if marks != nil {
		<-marks.done
	}
	return nil
}
func (m *Model) offlineTaskOwner() (*offlineTaskOwner, error) {
	if m.offlineTasks != nil {
		return m.offlineTasks, nil
	}
	owner := &offlineTaskOwner{}
	if err := m.offlineSession.registerViewCloser(owner, owner.Cancel); err != nil {
		return nil, err
	}
	m.offlineTasks = owner
	return owner, nil
}
