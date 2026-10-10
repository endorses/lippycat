//go:build cli || all

package email

// replayEmailFactory drains readers after the engine flushes all TCP streams,
// before normal shutdown cancels maintenance and reader contexts.
type replayEmailFactory struct{ *MultiProtocolFactory }

func (f *replayEmailFactory) Shutdown() error {
	f.streamWorkers.Wait()
	return f.MultiProtocolFactory.Shutdown()
}
