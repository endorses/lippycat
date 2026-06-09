package capture

import (
	"runtime/debug"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/tcpassembly"
)

// SafeFlushOlderThan wraps tcpassembly.Assembler.FlushOlderThan to log the
// stack trace on the intermittent gopacket@v1.1.19 "index out of range [-1]"
// panic in sendToConnection, then re-panics so the process restarts cleanly.
//
// Why not absorb the panic: the panicking goroutine is holding the
// assembler's internal connPool mutex when it explodes, and gopacket@v1.1.19
// does not use `defer mu.Unlock()`. Recovering leaks the mutex; every
// subsequent AssembleWithTimestamp/Flush call then deadlocks on it, and the
// consumer wedges silently for the lifetime of the process. Crashing and
// letting systemd restart the unit is the correct behaviour — the mutex
// only releases when the assembler is recreated.
func SafeFlushOlderThan(a *tcpassembly.Assembler, cutoff time.Time) (flushed, closed int) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("tcpassembly.FlushOlderThan panicked; crashing for restart",
				"panic", r,
				"stack", string(debug.Stack()),
			)
			panic(r)
		}
	}()
	return a.FlushOlderThan(cutoff)
}
