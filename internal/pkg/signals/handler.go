package signals

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// SetupHandler sets up a signal handler that cancels the provided context on SIGINT, SIGTERM, or SIGHUP
// Returns a cleanup function that should be called when the signal handler is no longer needed
func SetupHandler(ctx context.Context, cancel context.CancelFunc) (cleanup func()) {
	sigCh := make(chan os.Signal, constants.SignalChannelBuffer)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("Received signal, initiating shutdown", "signal", sig.String())
			cancel()
		case <-ctx.Done():
			// Context already cancelled, clean up
		}
	}()

	return func() {
		signal.Stop(sigCh)
		close(sigCh)
	}
}

// SetupHandlerWithCallback sets up a signal handler that calls the provided callback on signal receipt
// This is useful when you need custom shutdown logic instead of context cancellation
// Returns a cleanup function that should be called when the signal handler is no longer needed
func SetupHandlerWithCallback(ctx context.Context, onSignal func()) (cleanup func()) {
	sigCh := make(chan os.Signal, constants.SignalChannelBuffer)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case sig := <-sigCh:
			logger.Info("Received signal, invoking callback", "signal", sig.String())
			onSignal()
		case <-ctx.Done():
			// Context cancelled, no callback needed
		}
	}()

	return func() {
		signal.Stop(sigCh)
		close(sigCh)
		<-done // Wait for goroutine to exit
	}
}

// WaitForSignal blocks until a signal (SIGINT, SIGTERM, or SIGHUP) is received
// This is a simplified version for CLI tools that just need to wait for shutdown
func WaitForSignal() os.Signal {
	sigCh := make(chan os.Signal, constants.SignalChannelBuffer)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	sig := <-sigCh
	logger.Info("Received signal", "signal", sig.String())
	return sig
}
