//go:build li

package schema

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestNamespaceOutputEnforcesBudgetBeforeWrite(t *testing.T) {
	output := namespaceOutput{limit: 4}
	if n, err := output.Write([]byte("12345")); n != 0 || !errors.Is(err, ErrXMLSizeLimit) || output.buffer.Len() != 0 {
		t.Fatalf("oversized write: n=%d err=%v len=%d", n, err, output.buffer.Len())
	}
	if n, err := output.Write([]byte("1234")); n != 4 || err != nil {
		t.Fatalf("exact write: n=%d err=%v", n, err)
	}
	if n, err := output.Write([]byte("5")); n != 0 || !errors.Is(err, ErrXMLSizeLimit) || output.buffer.Len() != 4 {
		t.Fatalf("overflow write: n=%d err=%v len=%d", n, err, output.buffer.Len())
	}
}

func TestNamespaceNormalizationExactOutputBudget(t *testing.T) {
	input := []byte(`<root><leaf/></root>`)
	expected, err := NormalizeNamespacesBounded(input, MaxResponseXMLBytes)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := NormalizeNamespacesBounded(input, len(expected))
	if err != nil || !bytes.Equal(exact, expected) {
		t.Fatalf("exact bound: output=%q err=%v", exact, err)
	}
	short, err := NormalizeNamespacesBounded(input, len(expected)-1)
	if !errors.Is(err, ErrXMLSizeLimit) || short != nil {
		t.Fatalf("short bound: output=%q err=%v", short, err)
	}
	// A single large namespace declaration must also go through the bounded
	// writer; it cannot bypass the limit via a promoted WriteString method.
	largeURI := []byte(`<p:root xmlns:p="urn:` + strings.Repeat("x", 8192) + `"/>`)
	if output, err := NormalizeNamespacesBounded(largeURI, 4096); !errors.Is(err, ErrXMLSizeLimit) || output != nil {
		t.Fatalf("large URI: len=%d err=%v", len(output), err)
	}
}

func TestNamespaceNormalizationAvoidsUnusedDefaultCopies(t *testing.T) {
	unused := "urn:unused:" + strings.Repeat("x", 2048)
	input := []byte(`<x:root xmlns:x="` + X1Namespace + `" xmlns="` + unused + `">` + strings.Repeat(`<x:leaf/>`, 2000) + `</x:root>`)
	output, err := NormalizeNamespacesBounded(input, MaxResponseXMLBytes)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output, []byte(unused)) {
		t.Fatal("unused default namespace was copied into the normalized document")
	}
}

func TestNamespaceNormalizationBoundsUsedPrefixCopies(t *testing.T) {
	input := []byte(`<root xmlns:p="urn:` + strings.Repeat("x", 2048) + `">` + strings.Repeat(`<p:leaf/>`, 600) + `</root>`)
	if len(input) >= MaxResponseXMLBytes {
		t.Fatal("test input must fit the query wire budget")
	}
	output, err := NormalizeNamespacesBounded(input, MaxResponseXMLBytes)
	if !errors.Is(err, ErrXMLSizeLimit) || output != nil {
		t.Fatalf("used URI amplification: len=%d err=%v", len(output), err)
	}
}
