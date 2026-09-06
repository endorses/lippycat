package offline

import "github.com/endorses/lippycat/internal/pkg/offline/filterexpr"

// Expression is a validated immutable packet filter shared with query adapters.
type Expression = filterexpr.Expression
type ExpressionSpec = filterexpr.ExpressionSpec

// NewExpression validates and snapshots a storage filter expression.
func NewExpression(spec ExpressionSpec) (*Expression, error) { return filterexpr.NewExpression(spec) }
