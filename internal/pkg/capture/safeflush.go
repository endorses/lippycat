package capture

import (
	"runtime/debug"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/tcpassembly"
)

// SafeFlushOlderThan wraps tcpassembly.Assembler.FlushOlderThan with a
// recover() because gopacket@v1.1.19 has an intermittent
// "index out of range [-1]" panic in sendToConnection during flush bookkeeping.
// On panic, the flush is aborted, (0, 0) is returned, and the stack trace is
// logged. Letting the panic propagate kills the whole process.
func SafeFlushOlderThan(a *tcpassembly.Assembler, cutoff time.Time) (flushed, closed int) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("tcpassembly.FlushOlderThan recovered from panic",
				"panic", r,
				"stack", string(debug.Stack()),
			)
			flushed, closed = 0, 0
		}
	}()
	return a.FlushOlderThan(cutoff)
}
