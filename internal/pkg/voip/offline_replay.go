//go:build cli || all

package voip

import (
	"context"
	"errors"
)

// replaySIPStreamFactory drains parsers after ReassemblyEngine.Close has
// flushed and closed every input channel. Cancelling the factory immediately
// at EOF would discard queued SIP messages before the next replay pass.
// The assembler prevents further worker registration before calling Shutdown.
// Background maintenance workers are stopped by the regular factory shutdown.
type replaySIPStreamFactory struct {
	*sipStreamFactory
	ctx context.Context
}

func (f *replaySIPStreamFactory) Shutdown() error {
	done := make(chan struct{})
	go func() {
		f.streamWorkers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return f.sipStreamFactory.Shutdown()
	case <-f.ctx.Done():
		return errors.Join(f.ctx.Err(), f.sipStreamFactory.Shutdown())
	}
}
