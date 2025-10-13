package voip

import (
	"sync"

	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
)

// Shared variables and helpers used by both CLI and hunter builds

var (
	globalBufferMgr *BufferManager
	bufferOnce      sync.Once
)

// containsUserInHeaders checks if any of the SIP headers contain a surveiled user
func containsUserInHeaders(headers map[string]string) bool {
	for _, field := range []string{"from", "to", "p-asserted-identity"} {
		val := headers[field]
		if sipusers.IsSurveiled(val) {
			return true
		}
	}
	return false
}
