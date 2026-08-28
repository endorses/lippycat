//go:build !(cli || all)

package voip

func (tracker *CallTracker) closeAsyncWriter() {
	tracker.asyncWriterMu.Lock()
	defer tracker.asyncWriterMu.Unlock()
	if tracker.asyncWriter != nil {
		_ = tracker.asyncWriter.Stop()
		tracker.asyncWriter = nil
	}
}
