//go:build cli || all

package http

// replayHTTPFactory drains readers after the engine flushes all TCP streams.
// Cancelling the factory first can discard buffered headers at each replay EOF.
type replayHTTPFactory struct{ HTTPStreamFactory }

func (f *replayHTTPFactory) Shutdown() error {
	if factory, ok := f.HTTPStreamFactory.(*httpStreamFactory); ok {
		factory.streamWorkers.Wait()
	}
	return f.HTTPStreamFactory.Shutdown()
}
