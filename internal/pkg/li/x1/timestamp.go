//go:build li

package x1

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

// qualifiedMicrosecondLayout intentionally uses zeroes for a fixed-width,
// six-digit fractional component as required by QualifiedMicrosecondDateTime.
const qualifiedMicrosecondLayout = "2006-01-02T15:04:05.000000Z07:00"

// formatQualifiedMicrosecondDateTime preserves t's location offset and
// truncates, rather than rounds, any sub-microsecond precision.
func formatQualifiedMicrosecondDateTime(t time.Time) schema.QualifiedMicrosecondDateTime {
	return schema.QualifiedMicrosecondDateTime(t.Truncate(time.Microsecond).Format(qualifiedMicrosecondLayout))
}
