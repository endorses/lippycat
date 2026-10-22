//go:build li

package x1

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

func TestNamespaceRequestExpansionRejectsBeforeBatchMutation(t *testing.T) {
	manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
	server := NewServer(ServerConfig{}, nil, nil)
	server.objectManager = manager
	document := string(iriLexicalRequest(etsiX1Namespace, "x:CreateObjectRequest", iriLexicalRule("createObject", ` xmlns="`+IRIAdapterNamespace+`"`, "IRIRuleObject")))
	document = strings.Replace(document, `<x:X1Request`, `<x:X1Request xmlns:p="urn:`+strings.Repeat("x", 2048)+`"`, 1)
	second := `<x:x1RequestMessage xsi:type="x:PingRequest">` + iriLexicalBase() + strings.Repeat(`<p:leaf/>`, 6000) + `</x:x1RequestMessage>`
	document = strings.Replace(document, `</x:X1Request>`, second+`</x:X1Request>`, 1)
	require.Less(t, len(document), schema.MaxRequestXMLBytes)
	_, err := schema.NormalizeNamespacesBounded([]byte(document), schema.MaxRequestXMLBytes)
	require.ErrorIs(t, err, schema.ErrXMLSizeLimit)
	recorder := httptest.NewRecorder()
	server.handleX1Request(recorder, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(document)))
	require.Contains(t, recorder.Body.String(), "TopLevelErrorResponse")
	require.NotContains(t, recorder.Body.String(), "CreateObjectResponse")
	require.Zero(t, manager.seen)
	require.Empty(t, manager.objects)
}

func TestNamespaceQueryExpansionCannotConfirmSnapshot(t *testing.T) {
	document := string(iriLexicalSnapshot(etsiX1Namespace, iriLexicalRule("object", ` xmlns="`+IRIAdapterNamespace+`"`, "IRIRuleObject")))
	document = strings.Replace(document, `<x:X1Response`, `<x:X1Response xmlns:p="urn:`+strings.Repeat("x", 2048)+`"`, 1)
	document = strings.Replace(document, `<x:neStatusDetails>`, strings.Repeat(`<p:leaf/>`, 600)+`<x:neStatusDetails>`, 1)
	require.Less(t, len(document), schema.MaxResponseXMLBytes)
	snapshot, err := iriLexicalQuery(t, []byte(document))
	require.ErrorContains(t, err, schema.ErrXMLSizeLimit.Error())
	require.Nil(t, snapshot)
}
