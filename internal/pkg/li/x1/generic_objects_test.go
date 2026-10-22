//go:build li

package x1

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type mockObjectManager struct {
	objects  map[uuid.UUID]iripolicy.Object
	disabled bool
	seen     int
}

func (m *mockObjectManager) CreateGenericObject(value iripolicy.Object) error {
	if _, ok := m.objects[value.ID]; ok {
		return &ObjectError{Code: ErrorCodeObjectAlreadyExists, Message: "object already exists"}
	}
	m.objects[value.ID] = value
	m.seen++
	return nil
}
func (m *mockObjectManager) ModifyGenericObject(value iripolicy.Object) error {
	if _, ok := m.objects[value.ID]; !ok {
		return &ObjectError{Code: ErrorCodeObjectNotFound, Message: "object not found"}
	}
	m.objects[value.ID] = value
	m.seen++
	return nil
}
func (m *mockObjectManager) DeleteGenericObject(id uuid.UUID) error {
	if _, ok := m.objects[id]; !ok {
		return &ObjectError{Code: ErrorCodeObjectNotFound, Message: "object not found"}
	}
	delete(m.objects, id)
	return nil
}
func (m *mockObjectManager) GetGenericObject(id uuid.UUID) (iripolicy.Object, error) {
	value, ok := m.objects[id]
	if !ok {
		return value, &ObjectError{Code: ErrorCodeObjectNotFound, Message: "object not found"}
	}
	return value, nil
}
func (m *mockObjectManager) GetGenericObjects() ([]iripolicy.Object, error) {
	var values []iripolicy.Object
	for _, value := range m.objects {
		values = append(values, value)
	}
	return values, nil
}
func (m *mockObjectManager) DeleteAllGenericObjects() error {
	if m.disabled {
		return &ObjectError{Code: ErrorCodeDeleteAllObjectsDisabled, Message: "operation disabled by agreement"}
	}
	clear(m.objects)
	return nil
}

func testIRIRule() iripolicy.Object {
	return iripolicy.Object{ID: uuid.MustParse("12345678-1234-4234-8234-123456789abc"), Rule: &iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{{Owner: "ETSI", Name: "IRIEvents", Value: "All"}}}}, Action: iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: "NotDelivered"}}}
}
func validateIRIProfile(t *testing.T, data []byte) {
	t.Helper()
	tool, err := exec.LookPath("xmllint")
	if err != nil {
		t.Skip("xmllint is not installed")
	}
	path := filepath.Join(t.TempDir(), "message.xml")
	require.NoError(t, os.WriteFile(path, data, 0600))
	output, err := exec.Command(tool, "--nonet", "--noout", "--schema", "xsd/profile.xsd", path).CombinedOutput()
	require.NoError(t, err, "%s\n%s", output, data)
}

func TestGenericObjectsWireRoundTripAndSchema(t *testing.T) {
	manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
	server := NewServer(ServerConfig{}, nil, nil)
	server.objectManager = manager
	client := &Client{config: ClientConfig{Version: DefaultProtocolVersion, NEIdentifier: "test-ne"}, admfIdentifier: "test-admf"}
	rule := testIRIRule()
	policy := iripolicy.Object{ID: uuid.New(), Policy: &iripolicy.Policy{Name: "synthetic policy", Rules: []iripolicy.RuleReference{{Order: 2, ObjectID: rule.ID}}}}
	for _, value := range []iripolicy.Object{rule, policy} {
		request := &schema.CreateObjectRequest{X1RequestMessage: client.buildRequestMessage(), CreateObject: &schema.GenericObject{IRIObject: &value}}
		data, err := marshalWrappedRequest("CreateObjectRequest", request)
		require.NoError(t, err)
		validateIRIProfile(t, data)
		responses := server.processX1RequestEnvelope(data, "test")
		require.Len(t, responses, 1)
		require.IsType(t, &schema.CreateObjectResponse{}, responses[0])
		duplicate := server.processX1RequestEnvelope(data, "test")
		require.Equal(t, ErrorCodeObjectAlreadyExists, duplicate[0].(*schema.ErrorResponse).ErrorInformation.ErrorCode)
		objectID := schema.UUID(value.ID.String())
		get := &schema.GetObjectRequest{X1RequestMessage: client.buildRequestMessage(), ObjectId: &objectID}
		data, err = marshalWrappedRequest("GetObjectRequest", get)
		require.NoError(t, err)
		responses = server.processX1RequestEnvelope(data, "test")
		response, ok := responses[0].(*schema.GetObjectResponse)
		require.True(t, ok, "%#v", responses[0])
		wire, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
		require.NoError(t, err)
		validateIRIProfile(t, wire)
		normalized, err := schema.NormalizeNamespaces(wire)
		require.NoError(t, err)
		var container struct {
			Responses []schema.GetObjectResponse `xml:"x1ResponseMessage"`
		}
		require.NoError(t, xml.Unmarshal(normalized, &container))
		decoded, err := DecodeGenericObject(container.Responses[0].GenericObjectResponseDetails.Object)
		require.NoError(t, err)
		require.Equal(t, value, decoded)
	}
	require.Len(t, manager.objects, 2)
	for _, operation := range []string{"ListObjectsOfType", "GetAllGenericObjectDetails", "DeleteAllObjects"} {
		request := fmt.Sprintf(`<%sRequest xmlns="%s"><objectType>%s</objectType></%sRequest>`, operation, etsiX1Namespace, IRIPolicyObjectType, operation)
		if operation == "DeleteAllObjects" {
			request = `<DeleteAllObjectsRequest xmlns="` + etsiX1Namespace + `"/>`
		}
		response := server.processRequestMessage([]byte(request), client.buildRequestMessage(), "test")
		wire, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
		require.NoError(t, err)
		validateIRIProfile(t, wire)
	}
	require.Empty(t, manager.objects)
}

func TestGenericObjectInheritedNamespacesAndMalformedTypes(t *testing.T) {
	manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
	server := NewServer(ServerConfig{}, nil, nil)
	server.objectManager = manager
	original := `<X1Request xmlns="` + etsiX1Namespace + `" xmlns:xs="http://www.w3.org/2001/XMLSchema-instance" xmlns:x="` + etsiX1Namespace + `" xmlns:p="` + IRIAdapterNamespace + `" xmlns:i="` + schema.IRIPolicyNamespace + `" xmlns:d="` + schema.DictionaryNamespace + `"><x1RequestMessage xs:type="x:CreateObjectRequest"><version>` + DefaultProtocolVersion + `</version><createObject xs:type="p:IRIRuleObject"><objectId>12345678-1234-4234-8234-123456789abc</objectId><i:Criteria><i:Criteria><i:IRIEventCriteria><i:IRIEvents><d:Owner>ETSI</d:Owner><d:Name>IRIEvents</d:Name><d:Value>All</d:Value></i:IRIEvents></i:IRIEventCriteria></i:Criteria></i:Criteria><i:Action><d:Owner>ETSI</d:Owner><d:Name>IRIAction</d:Name><d:Value>NotDelivered</d:Value></i:Action></createObject></x1RequestMessage></X1Request>`
	responses := server.processX1RequestEnvelope([]byte(original), "test")
	require.IsType(t, &schema.CreateObjectResponse{}, responses[0])
	require.Equal(t, 1, manager.seen)
	mutations := []struct{ name, from, to string }{
		{"wrong request type namespace", `xs:type="x:CreateObjectRequest"`, `xs:type="p:CreateObjectRequest"`},
		{"unqualified type attribute", `xs:type="p:IRIRuleObject"`, `type="p:IRIRuleObject"`},
		{"unknown type namespace", `xmlns:p="` + IRIAdapterNamespace + `"`, `xmlns:p="urn:unknown"`},
		{"unknown field", `<i:Action>`, `<i:Unknown/><i:Action>`},
		{"duplicate action", `</i:Action>`, `</i:Action><i:Action/>`},
		{"mixed choices", `</i:IRIEventCriteria>`, `</i:IRIEventCriteria><i:NFTypeCriteria/>`},
		{"unknown attribute", `<i:Action>`, `<i:Action ignored="true">`},
		{"foreign namespace", `<d:Owner>ETSI</d:Owner>`, `<i:Owner>ETSI</i:Owner>`},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			body := strings.Replace(original, mutation.from, mutation.to, 1)
			responses := server.processX1RequestEnvelope([]byte(body), "test")
			require.IsType(t, &schema.ErrorResponse{}, responses[0])
			require.Equal(t, 1, manager.seen)
		})
	}
}

func TestGenericObjectClientRetainsInheritedNamespaces(t *testing.T) {
	value := testIRIRule()
	response := &schema.GetAllDetailsResponse{X1ResponseMessage: &schema.X1ResponseMessage{Version: DefaultProtocolVersion}, NeStatusDetails: &schema.NeStatusDetails{NeStatus: "OK"}, ListOfTaskResponseDetails: &schema.ListOfTaskResponseDetails{}, ListOfDestinationResponseDetails: &schema.ListOfDestinationResponseDetails{}, ListOfGenericObjectResponseDetails: &schema.ListOfGenericObjectResponseDetails{GenericObjectResponseDetails: []*schema.GenericObjectResponseDetails{genericObjectResponse(value)}}}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
		require.NoError(t, err)
		inherited := strings.ReplaceAll(string(wire), ` xmlns:iriAdapter="`+IRIAdapterNamespace+`"`, "")
		inherited = strings.Replace(inherited, `<X1Response `, `<X1Response xmlns:iriAdapter="`+IRIAdapterNamespace+`" `, 1)
		wire = []byte(inherited)
		_, err = w.Write(wire)
		require.NoError(t, err)
	}))
	defer peer.Close()
	client := &Client{config: ClientConfig{ADMFEndpoint: peer.URL, Version: DefaultProtocolVersion}, httpClient: peer.Client()}
	snapshot, err := client.GetAllDetails(context.Background())
	require.NoError(t, err)
	require.NotNil(t, snapshot.ListOfGenericObjectResponseDetails)
	decoded, err := DecodeGenericObject(snapshot.ListOfGenericObjectResponseDetails.GenericObjectResponseDetails[0].Object)
	require.NoError(t, err)
	require.Equal(t, value, decoded)
}

func TestIRIPolicyReferenceListsFailClosed(t *testing.T) {
	id := "12345678-1234-4234-8234-123456789abc"
	for _, test := range []struct {
		name, body string
		wantError  bool
	}{
		{"ordered references", `<listOfIRIPolicyReferences><iRIPolicyReference>` + id + `</iRIPolicyReference></listOfIRIPolicyReferences>`, false},
		{"explicit empty clears", `<listOfIRIPolicyReferences/>`, false},
		{"unknown child", `<listOfIRIPolicyReferences><ignored>` + id + `</ignored></listOfIRIPolicyReferences>`, true},
		{"wrong namespace", `<listOfIRIPolicyReferences xmlns="urn:unknown"/>`, true},
		{"duplicate list", `<listOfIRIPolicyReferences/><listOfIRIPolicyReferences/>`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := []byte(`<taskDetails xmlns="` + etsiX1Namespace + `">` + test.body + `</taskDetails>`)
			wire, err := schema.NormalizeNamespaces(wire)
			if err == nil {
				var details schema.TaskDetails
				err = xml.Unmarshal(wire, &details)
			}
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGenericObjectCRUDResponsesAndErrors(t *testing.T) {
	manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
	server := NewServer(ServerConfig{}, nil, nil)
	server.objectManager = manager
	client := &Client{config: ClientConfig{Version: DefaultProtocolVersion, NEIdentifier: "test-ne"}, admfIdentifier: "test-admf"}
	rule := testIRIRule()
	manager.objects[rule.ID] = rule
	rule.Rule.Action.Value = "Delivered"
	request := &schema.ModifyObjectRequest{X1RequestMessage: client.buildRequestMessage(), ModifyObject: &schema.GenericObject{IRIObject: &rule}}
	wire, err := marshalWrappedRequest("ModifyObjectRequest", request)
	require.NoError(t, err)
	validateIRIProfile(t, wire)
	responses := server.processX1RequestEnvelope(wire, "test")
	require.IsType(t, &schema.ModifyObjectResponse{}, responses[0])
	require.Equal(t, "Delivered", manager.objects[rule.ID].Rule.Action.Value)
	responseWire, err := xml.Marshal(&flexibleResponseContainer{Responses: responses})
	require.NoError(t, err)
	validateIRIProfile(t, responseWire)
	id := schema.UUID(rule.ID.String())
	deleteRequest := &schema.DeleteObjectRequest{X1RequestMessage: client.buildRequestMessage(), ObjectId: &id}
	wire, err = marshalWrappedRequest("DeleteObjectRequest", deleteRequest)
	require.NoError(t, err)
	responses = server.processX1RequestEnvelope(wire, "test")
	require.IsType(t, &schema.DeleteObjectResponse{}, responses[0])
	responseWire, err = xml.Marshal(&flexibleResponseContainer{Responses: responses})
	require.NoError(t, err)
	validateIRIProfile(t, responseWire)
	responses = server.processX1RequestEnvelope(wire, "test")
	missing := responses[0].(*schema.ErrorResponse)
	require.Equal(t, ErrorCodeObjectNotFound, missing.ErrorInformation.ErrorCode)
	require.Equal(t, "DeleteObject", missing.RequestMessageType)
	require.Nil(t, missing.ExtensionInformation)

	unknownType := "Q{urn:synthetic:unknown}Object"
	unknownWire, err := marshalWrappedRequest("ListObjectsOfTypeRequest", &schema.ListObjectsOfTypeRequest{X1RequestMessage: client.buildRequestMessage(), ObjectType: unknownType})
	require.NoError(t, err)
	unknownResponse := server.processX1RequestEnvelope(unknownWire, "test")
	require.Empty(t, unknownResponse[0].(*schema.ListObjectsOfTypeResponse).ListOfObjects.ObjectId)
	manager.disabled = true
	wire, err = marshalWrappedRequest("DeleteAllObjectsRequest", &schema.DeleteAllObjectsRequest{X1RequestMessage: client.buildRequestMessage()})
	require.NoError(t, err)
	responses = server.processX1RequestEnvelope(wire, "test")
	require.Equal(t, ErrorCodeDeleteAllObjectsDisabled, responses[0].(*schema.ErrorResponse).ErrorInformation.ErrorCode)
	ordinaryQName := IRIAdapterNamespace + ":IRIRuleObject"
	wire, err = marshalWrappedRequest("ListObjectsOfTypeRequest", &schema.ListObjectsOfTypeRequest{X1RequestMessage: client.buildRequestMessage(), ObjectType: ordinaryQName})
	require.NoError(t, err)
	responses = server.processX1RequestEnvelope(wire, "test")
	require.Equal(t, ErrorCodeObjectSyntax, responses[0].(*schema.ErrorResponse).ErrorInformation.ErrorCode)
}

func TestGenericObjectRequestRejectsDuplicateWrappers(t *testing.T) {
	manager := &mockObjectManager{objects: map[uuid.UUID]iripolicy.Object{}}
	server := NewServer(ServerConfig{}, nil, nil)
	server.objectManager = manager
	response := server.processRequestMessage([]byte(`<CreateObjectRequest xmlns="`+etsiX1Namespace+`"><createObject/><createObject/></CreateObjectRequest>`), nil, "test")
	require.Equal(t, ErrorCodeObjectSyntax, response.(*schema.ErrorResponse).ErrorInformation.ErrorCode)
	require.Zero(t, manager.seen)
}

func TestPolicyNamespaceShadowingAndWholeDocumentValidation(t *testing.T) {
	wire := `<root xmlns="` + etsiX1Namespace + `" xmlns:a="` + IRIAdapterNamespace + `" xmlns:xsi="` + schema.XSINamespace + `"><object xmlns:a="urn:untrusted" xsi:type="a:IRIRuleObject"><objectId>12345678-1234-4234-8234-123456789abc</objectId></object></root>`
	normalized, err := schema.NormalizeNamespaces([]byte(wire))
	require.NoError(t, err)
	var result struct {
		Object schema.GenericObject `xml:"object"`
	}
	require.Error(t, xml.Unmarshal(normalized, &result))
	for _, document := range []string{`<root/><other/>`, `<root/>ignored`, `ignored<root/>`, `<root>`} {
		_, err := schema.NormalizeNamespaces([]byte(document))
		require.Error(t, err)
	}
}

func TestGenericObjectQueryBodyLimit(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`<X1Response/>` + strings.Repeat(" ", 1024*1024)))
		require.NoError(t, err)
	}))
	defer peer.Close()
	client := &Client{config: ClientConfig{ADMFEndpoint: peer.URL, Version: DefaultProtocolVersion}, httpClient: peer.Client()}
	_, err := client.GetAllGenericObjectDetails(context.Background())
	require.ErrorContains(t, err, "body size limit")
}
