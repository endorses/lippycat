//go:build tui || all

package filters

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// BooleanOperator represents logical operators
type BooleanOperator int

const (
	OpAND BooleanOperator = iota
	OpOR
	OpNOT
)

// BooleanFilter represents a filter expression with boolean operators
type BooleanFilter struct {
	operator BooleanOperator
	left     Filter
	right    Filter // nil for NOT operator
	expr     string // original expression
}

// NewBooleanFilter creates a new boolean filter
func NewBooleanFilter(operator BooleanOperator, left, right Filter, expr string) *BooleanFilter {
	return &BooleanFilter{
		operator: operator,
		left:     left,
		right:    right,
		expr:     expr,
	}
}

// Match implements the Filter interface
func (bf *BooleanFilter) Match(packet components.PacketDisplay) bool {
	switch bf.operator {
	case OpAND:
		return bf.left.Match(packet) && bf.right.Match(packet)
	case OpOR:
		return bf.left.Match(packet) || bf.right.Match(packet)
	case OpNOT:
		return !bf.left.Match(packet)
	default:
		return false
	}
}

// String implements the Filter interface
func (bf *BooleanFilter) String() string {
	if bf.expr != "" {
		return bf.expr
	}

	switch bf.operator {
	case OpAND:
		return bf.left.String() + " AND " + bf.right.String()
	case OpOR:
		return bf.left.String() + " OR " + bf.right.String()
	case OpNOT:
		return "NOT " + bf.left.String()
	default:
		return ""
	}
}

// Type implements the Filter interface
func (bf *BooleanFilter) Type() string {
	return "boolean"
}

// Selectivity returns how selective this filter is (0.0-1.0)
// Boolean selectivity depends on the operator and child selectivity
func (bf *BooleanFilter) Selectivity() float64 {
	switch bf.operator {
	case OpAND:
		// AND: average of children (both must match)
		if bf.left != nil && bf.right != nil {
			return (bf.left.Selectivity() + bf.right.Selectivity()) / 2.0
		}
		return 0.5
	case OpOR:
		// OR: minimum of children (least selective child determines)
		if bf.left != nil && bf.right != nil {
			leftSel := bf.left.Selectivity()
			rightSel := bf.right.Selectivity()
			if leftSel < rightSel {
				return leftSel
			}
			return rightSel
		}
		return 0.5
	case OpNOT:
		// NOT: inverse of child selectivity
		if bf.left != nil {
			return 1.0 - bf.left.Selectivity()
		}
		return 0.5
	default:
		return 0.5
	}
}

// ParseBooleanExpression parses a filter expression with boolean operators
// Supported syntax:
//   - "expr1 AND expr2" - both must match
//   - "expr1 OR expr2"  - either must match
//   - "NOT expr"        - must not match
//   - "expr1 && expr2"  - shorthand for AND
//   - "expr1 || expr2"  - shorthand for OR
//   - "!expr"           - shorthand for NOT
//   - Parentheses for grouping: "(expr1 OR expr2) AND expr3"
func ParseBooleanExpression(expr string, parseSimpleFilter func(string) Filter) (Filter, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}

	// Try to parse as boolean expression
	filter := parseBooleanExpr(expr, parseSimpleFilter)
	if filter != nil {
		return filter, nil
	}

	// Fall back to simple filter
	return parseSimpleFilter(expr), nil
}

// parseBooleanExpr recursively parses boolean expressions
func parseBooleanExpr(expr string, parseSimpleFilter func(string) Filter) Filter {
	expr = strings.TrimSpace(expr)

	// Handle parentheses
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		// Check if parentheses are balanced and outermost
		if isBalancedOutermost(expr) {
			inner := expr[1 : len(expr)-1]
			return parseBooleanExpr(inner, parseSimpleFilter)
		}
	}

	// Look for OR operator (lowest precedence)
	if filter := parseOR(expr, parseSimpleFilter); filter != nil {
		return filter
	}

	// Look for AND operator (higher precedence than OR)
	if filter := parseAND(expr, parseSimpleFilter); filter != nil {
		return filter
	}

	// Look for NOT operator (highest precedence)
	if filter := parseNOT(expr, parseSimpleFilter); filter != nil {
		return filter
	}

	// No boolean operators found, return nil to fall back to simple filter
	return nil
}

// parseOR looks for OR operators outside of parentheses
func parseOR(expr string, parseSimpleFilter func(string) Filter) Filter {
	// Try "||" first
	if idx := findOperator(expr, "||"); idx != -1 {
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+2:])
		leftFilter := parseBooleanExpr(left, parseSimpleFilter)
		if leftFilter == nil {
			leftFilter = parseSimpleFilter(left)
		}
		rightFilter := parseBooleanExpr(right, parseSimpleFilter)
		if rightFilter == nil {
			rightFilter = parseSimpleFilter(right)
		}
		return NewBooleanFilter(OpOR, leftFilter, rightFilter, expr)
	}

	// Try " OR " (case insensitive, word boundary)
	if idx := findOperatorWord(expr, "OR"); idx != -1 {
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+2:])
		leftFilter := parseBooleanExpr(left, parseSimpleFilter)
		if leftFilter == nil {
			leftFilter = parseSimpleFilter(left)
		}
		rightFilter := parseBooleanExpr(right, parseSimpleFilter)
		if rightFilter == nil {
			rightFilter = parseSimpleFilter(right)
		}
		return NewBooleanFilter(OpOR, leftFilter, rightFilter, expr)
	}

	return nil
}

// parseAND looks for AND operators outside of parentheses
func parseAND(expr string, parseSimpleFilter func(string) Filter) Filter {
	// Try "&&" first
	if idx := findOperator(expr, "&&"); idx != -1 {
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+2:])
		leftFilter := parseBooleanExpr(left, parseSimpleFilter)
		if leftFilter == nil {
			leftFilter = parseSimpleFilter(left)
		}
		rightFilter := parseBooleanExpr(right, parseSimpleFilter)
		if rightFilter == nil {
			rightFilter = parseSimpleFilter(right)
		}
		return NewBooleanFilter(OpAND, leftFilter, rightFilter, expr)
	}

	// Try " AND " (case insensitive, word boundary)
	if idx := findOperatorWord(expr, "AND"); idx != -1 {
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+3:])
		leftFilter := parseBooleanExpr(left, parseSimpleFilter)
		if leftFilter == nil {
			leftFilter = parseSimpleFilter(left)
		}
		rightFilter := parseBooleanExpr(right, parseSimpleFilter)
		if rightFilter == nil {
			rightFilter = parseSimpleFilter(right)
		}
		return NewBooleanFilter(OpAND, leftFilter, rightFilter, expr)
	}

	return nil
}

// parseNOT looks for NOT operators
func parseNOT(expr string, parseSimpleFilter func(string) Filter) Filter {
	// Try "!" prefix
	if strings.HasPrefix(expr, "!") {
		inner := strings.TrimSpace(expr[1:])
		innerFilter := parseBooleanExpr(inner, parseSimpleFilter)
		if innerFilter == nil {
			innerFilter = parseSimpleFilter(inner)
		}
		return NewBooleanFilter(OpNOT, innerFilter, nil, expr)
	}

	// Try "NOT " prefix (case insensitive, word boundary)
	if len(expr) >= 4 {
		prefix := strings.ToUpper(expr[:4])
		if prefix == "NOT " {
			inner := strings.TrimSpace(expr[4:])
			innerFilter := parseBooleanExpr(inner, parseSimpleFilter)
			if innerFilter == nil {
				innerFilter = parseSimpleFilter(inner)
			}
			return NewBooleanFilter(OpNOT, innerFilter, nil, expr)
		}
	}

	return nil
}

// findOperator finds the position of an operator outside of parentheses
func findOperator(expr string, op string) int {
	depth := 0
	for i := 0; i < len(expr); i++ {
		if expr[i] == '(' {
			depth++
		} else if expr[i] == ')' {
			depth--
		} else if depth == 0 {
			if i+len(op) <= len(expr) && expr[i:i+len(op)] == op {
				return i
			}
		}
	}
	return -1
}

// findOperatorWord finds a word operator (AND, OR, NOT) outside of parentheses
func findOperatorWord(expr string, op string) int {
	opUpper := strings.ToUpper(op)
	depth := 0

	for i := 0; i < len(expr); i++ {
		if expr[i] == '(' {
			depth++
		} else if expr[i] == ')' {
			depth--
		} else if depth == 0 {
			// Check if we have enough space for " OP "
			if i > 0 && i+len(op)+1 < len(expr) {
				// Must be surrounded by whitespace
				if expr[i-1] == ' ' && expr[i+len(op)] == ' ' {
					candidate := strings.ToUpper(expr[i : i+len(op)])
					if candidate == opUpper {
						return i
					}
				}
			}
		}
	}
	return -1
}

// isBalancedOutermost checks if the outer parentheses are balanced and outermost
func isBalancedOutermost(expr string) bool {
	if !strings.HasPrefix(expr, "(") || !strings.HasSuffix(expr, ")") {
		return false
	}

	depth := 0
	for i, ch := range expr {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			// If we hit zero before the end, the outer parens aren't outermost
			if depth == 0 && i < len(expr)-1 {
				return false
			}
		}
	}

	return depth == 0
}
