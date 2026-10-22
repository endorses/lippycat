//go:build li

package x1

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

const lexicalRuleID = "12345678-1234-4234-8234-123456789abc"
const lexicalPolicyID = "12345678-1234-4234-8234-123456789abe"

func iriLexicalNamespaces(defaultNamespace string) string {
	return ` xmlns:x="` + etsiX1Namespace + `" xmlns:xsi="` + schema.XSINamespace + `" xmlns:i="` + schema.IRIPolicyNamespace + `" xmlns:d="` + schema.DictionaryNamespace + `" xmlns="` + defaultNamespace + `"`
}
func iriLexicalBase() string {
	return `<x:admfIdentifier>example-admf</x:admfIdentifier><x:neIdentifier>example-ne</x:neIdentifier><x:messageTimestamp>2026-10-22T12:00:00.000000Z</x:messageTimestamp><x:version>v1.23.1</x:version><x:x1TransactionId>12345678-1234-4234-8234-123456789abd</x:x1TransactionId>`
}
func iriLexicalRule(element, declaration, typeName string) string {
	return `<x:` + element + declaration + ` xsi:type="` + typeName + `"><x:objectId>` + lexicalRuleID + `</x:objectId><i:Criteria><i:Criteria><i:IRIEventCriteria><i:IRIEvents><d:Owner>ETSI</d:Owner><d:Name>IRIEvents</d:Name><d:Value>All</d:Value></i:IRIEvents></i:IRIEventCriteria></i:Criteria></i:Criteria><i:Action><d:Owner>ETSI</d:Owner><d:Name>IRIAction</d:Name><d:Value>NotDelivered</d:Value></i:Action></x:` + element + `>`
}
func iriLexicalPolicy(element, order string) string {
	return `<x:` + element + ` xmlns:p="` + IRIAdapterNamespace + `" xsi:type="p:IRIPolicyObject"><x:objectId>` + lexicalPolicyID + `</x:objectId><i:IRIRules><i:IRIRuleReference><i:Order>` + order + `</i:Order><i:ObjectIdentifier>` + lexicalRuleID + `</i:ObjectIdentifier></i:IRIRuleReference></i:IRIRules></x:` + element + `>`
}
func iriLexicalRequest(defaultNamespace, messageType, object string) []byte {
	return []byte(`<x:X1Request` + iriLexicalNamespaces(defaultNamespace) + `><x:x1RequestMessage xsi:type="` + messageType + `">` + iriLexicalBase() + object + `</x:x1RequestMessage></x:X1Request>`)
}
func iriLexicalSnapshot(defaultNamespace, object string) []byte {
	return []byte(`<x:X1Response` + iriLexicalNamespaces(defaultNamespace) + `><x:x1ResponseMessage xsi:type="x:GetAllDetailsResponse">` + iriLexicalBase() + `<x:neStatusDetails><x:neStatus>OK</x:neStatus><x:listOfFaults/></x:neStatusDetails><x:listOfTaskResponseDetails/><x:listOfDestinationResponseDetails/><x:listOfGenericObjectResponseDetails><x:genericObjectResponseDetails>` + object + `</x:genericObjectResponseDetails></x:listOfGenericObjectResponseDetails></x:x1ResponseMessage></x:X1Response>`)
}
func iriLexicalQuery(t *testing.T, document []byte) (*schema.GetAllDetailsResponse, error) {
	t.Helper()
	client := &Client{config: ClientConfig{ADMFEndpoint: "http://admf.example.test", Version: DefaultProtocolVersion}, httpClient: &http.Client{Transport: startupTransportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(document)), Header: make(http.Header)}, nil
	})}}
	return client.GetAllDetails(context.Background())
}

func TestIRIQNameDefaultNamespaceRoutingAndQuery(t *testing.T) {
	for _, test := range []struct{ name, outer, declaration, typeName string }{
		{"local default", etsiX1Namespace, ` xmlns="` + IRIAdapterNamespace + `"`, "IRIRuleObject"},
		{"inherited default", IRIAdapterNamespace, "", "IRIRuleObject"},
		{"local override", "urn:synthetic:foreign", ` xmlns="` + IRIAdapterNamespace + `"`, "IRIRuleObject"},
		{"QName whitespace", IRIAdapterNamespace, "", " &#x9; IRIRuleObject &#xD;&#xA; "},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := iriLexicalRequest(test.outer, "x:CreateObjectRequest", iriLexicalRule("createObject", test.declaration, test.typeName))
			validateIRILexicalDocument(t, request, test.name == "QName whitespace")
			manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
			server := NewServer(ServerConfig{}, nil, nil)
			server.objectManager = manager
			responses := server.processX1RequestEnvelope(request, "test")
			require.IsType(t, &schema.CreateObjectResponse{}, responses[0])
			require.Equal(t, 1, manager.seen)
			document := iriLexicalSnapshot(test.outer, iriLexicalRule("object", test.declaration, test.typeName))
			validateIRILexicalDocument(t, document, test.name == "QName whitespace")
			snapshot, err := iriLexicalQuery(t, document)
			require.NoError(t, err)
			object, err := DecodeGenericObject(snapshot.ListOfGenericObjectResponseDetails.GenericObjectResponseDetails[0].Object)
			require.NoError(t, err)
			require.Equal(t, uuid.MustParse(lexicalRuleID), object.ID)
			require.NotNil(t, object.Rule)
		})
	}
}

func TestIRIQNameForeignAndEmptyDefaultsRemainRejected(t *testing.T) {
	for _, test := range []struct{ name, outer, messageType, objectType string }{
		{"foreign object default", "urn:synthetic:foreign", "x:CreateObjectRequest", "IRIRuleObject"},
		{"empty object default", "", "x:CreateObjectRequest", "IRIRuleObject"},
		{"foreign request default", "urn:synthetic:foreign", "CreateObjectRequest", "IRIRuleObject"},
		{"empty request default", "", "CreateObjectRequest", "IRIRuleObject"},
		{"QName internal whitespace", IRIAdapterNamespace, "x:CreateObjectRequest", "IRI RuleObject"},
		{"QName non-XML whitespace", IRIAdapterNamespace, "x:CreateObjectRequest", "&#xA0;IRIRuleObject"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := iriLexicalRequest(test.outer, test.messageType, iriLexicalRule("createObject", "", test.objectType))
			manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
			server := NewServer(ServerConfig{}, nil, nil)
			server.objectManager = manager
			responses := server.processX1RequestEnvelope(request, "test")
			require.IsType(t, &schema.ErrorResponse{}, responses[0])
			require.Empty(t, manager.objects)
			snapshot, err := iriLexicalQuery(t, iriLexicalSnapshot(test.outer, iriLexicalRule("object", "", test.objectType)))
			require.Error(t, err)
			require.Nil(t, snapshot)
		})
	}
}

func TestIRIXMLRejectsDuplicateExpandedAttributes(t *testing.T) {
	for _, attributes := range []string{
		`xsi:type="" xsi:type="IRIRuleObject"`,
		`xsi:type="" xmlns:alias="` + schema.XSINamespace + `" alias:type="IRIRuleObject"`,
		`xsi:type="IRIRuleObject" xmlns:alias="` + schema.XSINamespace + `" alias:type="IRIRuleObject"`,
		`xsi:type="IRIRuleObject" xmlns:a="urn:attribute" xmlns:b="urn:attribute" a:value="" b:value="same"`,
	} {
		t.Run(attributes, func(t *testing.T) {
			scalar := []byte(`<x:object` + iriLexicalNamespaces(IRIAdapterNamespace) + ` ` + attributes + `/>`)
			_, err := schema.NormalizeNamespaces(scalar)
			require.Error(t, err)
			token, err := xml.NewDecoder(bytes.NewReader(scalar)).Token()
			require.NoError(t, err)
			_, err = schema.ResolveType(token.(xml.StartElement))
			require.Error(t, err)
			object := strings.Replace(iriLexicalRule("createObject", "", "IRIRuleObject"), `xsi:type="IRIRuleObject"`, attributes, 1)
			manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
			server := NewServer(ServerConfig{}, nil, nil)
			server.objectManager = manager
			responses := server.processX1RequestEnvelope(iriLexicalRequest(IRIAdapterNamespace, "x:CreateObjectRequest", object), "test")
			require.IsType(t, &schema.ErrorResponse{}, responses[0])
			require.Empty(t, manager.objects)
			snapshot, err := iriLexicalQuery(t, iriLexicalSnapshot(IRIAdapterNamespace, strings.ReplaceAll(object, "x:createObject", "x:object")))
			require.Error(t, err)
			require.Nil(t, snapshot)
		})
	}
}

func TestIRIPositiveIntegerLexicalRoutingAndQuery(t *testing.T) {
	for _, test := range []struct {
		lexical string
		order   uint64
		valid   bool
	}{
		{"1", 1, true}, {" 1 ", 1, true}, {"+1", 1, true}, {" &#x9; +1 &#xD;&#xA; ", 1, true}, {"+0001", 1, true},
		{"18446744073709551615", ^uint64(0), true},
		{"0", 0, false}, {"+0", 0, false}, {"-1", 0, false}, {"+ 1", 0, false}, {"++1", 0, false}, {"1 2", 0, false}, {"&#xA0;1", 0, false}, {"18446744073709551616", 0, false},
	} {
		t.Run(test.lexical, func(t *testing.T) {
			request := iriLexicalRequest(etsiX1Namespace, "x:CreateObjectRequest", iriLexicalPolicy("createObject", test.lexical))
			document := iriLexicalSnapshot(etsiX1Namespace, iriLexicalPolicy("object", test.lexical))
			if test.valid {
				validateIRIProfile(t, request)
				validateIRIProfile(t, document)
			}
			manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
			server := NewServer(ServerConfig{}, nil, nil)
			server.objectManager = manager
			responses := server.processX1RequestEnvelope(request, "test")
			snapshot, err := iriLexicalQuery(t, document)
			if !test.valid {
				require.IsType(t, &schema.ErrorResponse{}, responses[0])
				require.Empty(t, manager.objects)
				require.Error(t, err)
				require.Nil(t, snapshot)
				return
			}
			require.IsType(t, &schema.CreateObjectResponse{}, responses[0])
			require.Equal(t, test.order, manager.objects[uuid.MustParse(lexicalPolicyID)].Policy.Rules[0].Order)
			require.NoError(t, err)
			object, err := DecodeGenericObject(snapshot.ListOfGenericObjectResponseDetails.GenericObjectResponseDetails[0].Object)
			require.NoError(t, err)
			require.Equal(t, test.order, object.Policy.Rules[0].Order)
		})
	}
}

func validateIRILexicalDocument(t *testing.T, document []byte, qnameWhitespace bool) {
	t.Helper()
	if qnameWhitespace {
		// libxml2's xsi:type dispatch does not collapse QName whitespace. Validate
		// its canonical form against the real XSD while routing the original form.
		normalized, err := schema.NormalizeNamespaces(document)
		require.NoError(t, err)
		document = normalized
	}
	validateIRIProfile(t, document)
}

func TestIRIQNameDefaultScopeRestoresBetweenSiblings(t *testing.T) {
	document := `<root xmlns="` + IRIAdapterNamespace + `" xmlns:x="` + etsiX1Namespace + `" xmlns:xsi="` + schema.XSINamespace + `"><x:object xmlns="urn:synthetic:foreign" xsi:type="IRIRuleObject"/><x:object xsi:type="IRIRuleObject"/><x:object xmlns="" xsi:type="IRIRuleObject"/><x:object xsi:type="IRIRuleObject"/></root>`
	normalized, err := schema.NormalizeNamespaces([]byte(document))
	require.NoError(t, err)
	decoder := xml.NewDecoder(bytes.NewReader(normalized))
	var actual []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "object" {
			typ, err := schema.ResolveType(start)
			require.NoError(t, err)
			actual = append(actual, typ.Space)
		}
	}
	require.Equal(t, []string{"urn:synthetic:foreign", IRIAdapterNamespace, "", IRIAdapterNamespace}, actual)
}

func TestIRIQNameWhitespaceOnEnvelope(t *testing.T) {
	request := iriLexicalRequest(IRIAdapterNamespace, " &#x9; x:CreateObjectRequest &#xD;&#xA; ", iriLexicalRule("createObject", "", "IRIRuleObject"))
	validateIRILexicalDocument(t, request, true)
	manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
	server := NewServer(ServerConfig{}, nil, nil)
	server.objectManager = manager
	responses := server.processX1RequestEnvelope(request, "test")
	require.IsType(t, &schema.CreateObjectResponse{}, responses[0])
	require.Equal(t, 1, manager.seen)
	document := bytes.Replace(iriLexicalSnapshot(IRIAdapterNamespace, iriLexicalRule("object", "", "IRIRuleObject")), []byte(`xsi:type="x:GetAllDetailsResponse"`), []byte(`xsi:type=" &#x9; x:GetAllDetailsResponse &#xD;&#xA; "`), 1)
	validateIRILexicalDocument(t, document, true)
	snapshot, err := iriLexicalQuery(t, document)
	require.NoError(t, err)
	require.Len(t, snapshot.ListOfGenericObjectResponseDetails.GenericObjectResponseDetails, 1)
}

func TestIRIQNameLegacyContainerDoesNotRelaxETSIEnvelope(t *testing.T) {
	for _, root := range []string{"requestContainer", "X1Request"} {
		t.Run(root, func(t *testing.T) {
			document := []byte(`<` + root + ` xmlns:xsi="` + schema.XSINamespace + `"><x1RequestMessage xsi:type="pingRequest"><version>` + DefaultProtocolVersion + `</version></x1RequestMessage></` + root + `>`)
			server := NewServer(ServerConfig{}, nil, nil)
			recorder := httptest.NewRecorder()
			server.handleX1Request(recorder, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(document)))
			require.Equal(t, http.StatusOK, recorder.Code)
			if root == "requestContainer" {
				require.Contains(t, recorder.Body.String(), `xsi:type="PingResponse"`)
			} else {
				require.Contains(t, recorder.Body.String(), `xsi:type="ErrorResponse"`)
			}
		})
	}
}
