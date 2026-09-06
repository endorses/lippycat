package filterexpr

import (
	"strings"
	"testing"
)

func TestExpressionValidationAndOwnership(t *testing.T) {
	for _, s := range []ExpressionSpec{{Op: "bad"}, {Op: "not"}, {Op: "and", Children: []*Expression{nil}}, {Op: "numeric", Fields: []string{"length"}, Comparison: "!="}, {Op: "cidr", Fields: []string{"src"}, Text: "bad"}, {Op: "all", Children: []*Expression{{}}}} {
		if _, err := NewExpression(s); err == nil {
			t.Fatalf("accepted invalid expression %+v", s)
		}
	}
	fields := []string{"src"}
	e, err := NewExpression(ExpressionSpec{Op: "text", Fields: fields, Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	fields[0] = "info"
	got := e.RequiredFields()
	got[0] = "node"
	if e.RequiredFields()[0] != "src" {
		t.Fatal("mutable dependencies")
	}
	child := e
	for i := 0; i < 100; i++ {
		next, err := NewExpression(ExpressionSpec{Op: "not", Children: []*Expression{child}})
		if err != nil {
			return
		}
		child = next
	}
	t.Fatal("accepted unbounded depth")
}

func TestExpressionDependenciesAndBytes(t *testing.T) {
	for _, op := range []string{"node", "voip"} {
		e, err := NewExpression(ExpressionSpec{Op: op, Fields: []string{"unrelated"}})
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Join(e.RequiredFields(), ",")
		if strings.Contains(fields, "unrelated") {
			t.Fatal("accepted false dependencies")
		}
		if op == "node" && fields != "node" {
			t.Fatal(fields)
		}
		if op == "voip" && !strings.Contains(fields, "sip.user") {
			t.Fatal(fields)
		}
	}
	if _, err := NewExpression(ExpressionSpec{Op: "text", Fields: []string{"info"}, Text: strings.Repeat("x", 1<<20)}); err == nil {
		t.Fatal("accepted oversized text")
	}
	leaf, err := NewExpression(ExpressionSpec{Op: "text", Fields: []string{"info"}, Text: strings.Repeat("x", 1<<19)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewExpression(ExpressionSpec{Op: "and", Children: []*Expression{leaf, leaf}}); err == nil {
		t.Fatal("accepted oversized aggregate")
	}
}
