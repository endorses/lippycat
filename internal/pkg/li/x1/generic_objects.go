//go:build li

package x1

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
)

// Generic-object operation errors from TS 103 221-1 table 6.7-3.
const (
	ErrorCodeObjectAlreadyExists      = 2050
	ErrorCodeObjectNotFound           = 2060
	ErrorCodeCreateObject             = 8500
	ErrorCodeModifyObject             = 8510
	ErrorCodeDeleteObject             = 8530
	ErrorCodeDeleteAllObjects         = 8540
	ErrorCodeDeleteAllObjectsDisabled = 8550
	ErrorCodeObjectSyntax             = 1010
	IRIAdapterNamespace               = schema.IRIAdapterNamespace
	IRIPolicyObjectType               = "Q{" + IRIAdapterNamespace + "}IRIPolicyObject"
	IRIRuleObjectType                 = "Q{" + IRIAdapterNamespace + "}IRIRuleObject"
)

var genericObjectTypePattern = regexp.MustCompile(`^Q\{[^{}]*\}.+$`)

// ObjectError reports an operation-specific error without including policy data.
type ObjectError struct {
	Code    int
	Message string
}

func (err *ObjectError) Error() string { return err.Message }

// GenericObjectManager provides transactional administration of IRI objects.
// Implementations own generation assignment and dependent-task revocation.
type GenericObjectManager interface {
	CreateGenericObject(iripolicy.Object) error
	ModifyGenericObject(iripolicy.Object) error
	DeleteGenericObject(uuid.UUID) error
	GetGenericObject(uuid.UUID) (iripolicy.Object, error)
	GetGenericObjects() ([]iripolicy.Object, error)
	DeleteAllGenericObjects() error
}

// DecodeGenericObject returns a detached supported generic-object definition.
func DecodeGenericObject(value *schema.GenericObject) (iripolicy.Object, error) {
	if value == nil || value.IRIObject == nil {
		return iripolicy.Object{}, errors.New("unsupported generic object")
	}

	clone := iripolicy.CloneObject(*value.IRIObject)
	if clone.ID == uuid.Nil || (clone.Policy == nil) == (clone.Rule == nil) {
		return iripolicy.Object{}, errors.New("invalid generic object")
	}
	if value.ObjectId != nil && string(*value.ObjectId) != clone.ID.String() {
		return iripolicy.Object{}, errors.New("inconsistent generic object identifier")
	}
	clone.Generation = 0
	return clone, nil
}
func genericObjectResponse(value iripolicy.Object) *schema.GenericObjectResponseDetails {
	id := schema.UUID(value.ID.String())
	return &schema.GenericObjectResponseDetails{Object: &schema.GenericObject{ObjectId: &id, IRIObject: &value}}
}

// ParseIRIPolicyReferences validates the ordered task policy-reference list.
func ParseIRIPolicyReferences(value *schema.ListOfIRIPolicyReferences) ([]uuid.UUID, error) {
	if value == nil {
		return nil, nil
	}
	if len(value.IRIPolicyReference) > 256 {
		return nil, errors.New("IRI policy reference limit exceeded")
	}
	result := make([]uuid.UUID, 0, len(value.IRIPolicyReference))
	seen := map[uuid.UUID]bool{}
	for _, ref := range value.IRIPolicyReference {
		if ref == nil {
			return nil, errors.New("nil IRI policy reference")
		}
		id, err := uuid.Parse(string(*ref))
		if err != nil || id == uuid.Nil || seen[id] {
			return nil, errors.New("invalid or duplicate IRI policy reference")
		}
		seen[id] = true
		result = append(result, id)
	}
	return result, nil
}

func iriPolicyReferenceResponse(refs []uuid.UUID) *schema.ListOfIRIPolicyReferences {
	if refs == nil {
		return nil
	}
	result := &schema.ListOfIRIPolicyReferences{}
	for _, ref := range refs {
		id := schema.UUID(ref.String())
		result.IRIPolicyReference = append(result.IRIPolicyReference, &id)
	}
	return result
}

func (message *x1RequestMessageAttr) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	type plain x1RequestMessageAttr
	var value plain
	if err := decoder.DecodeElement(&value, &start); err != nil {
		return err
	}
	*message = x1RequestMessageAttr(value)
	typ, err := schema.ResolveType(start)
	if err != nil {
		message.TypeError = err.Error()
		return nil
	}
	message.Type = typ.Local
	message.TypeNamespace = typ.Space
	return nil
}

func (s *Server) genericOperationError(req *schema.X1RequestMessage, operation string, fallback int, err error) any {
	var objectError *ObjectError
	if errors.As(err, &objectError) {
		return s.buildErrorResponse(req, operation, objectError.Code, objectError.Message)
	}
	return s.buildErrorResponse(req, operation, fallback, "generic object operation failed")
}
func (s *Server) processGenericObjectRequest(body []byte, base *schema.X1RequestMessage, name string) (any, bool) {
	operation := strings.TrimSuffix(name, "Request")
	if len(operation) > 0 {
		operation = strings.ToUpper(operation[:1]) + operation[1:]
	}
	switch operation {
	case "CreateObject", "ModifyObject", "DeleteObject", "GetObject", "ListObjectsOfType", "DeleteAllObjects", "GetAllGenericObjectDetails":
	default:
		return nil, false
	}
	if err := validateGenericRequest(body, operation); err != nil {
		return s.buildErrorResponse(base, operation, ErrorCodeObjectSyntax, "invalid generic object request"), true
	}
	if s.objectManager == nil {
		return s.buildErrorResponse(base, operation, 1080, "generic object administration is not configured"), true
	}
	failure := func(err error) any {
		return s.buildErrorResponse(base, operation, ErrorCodeObjectSyntax, "invalid generic object request")
	}
	switch operation {
	case "CreateObject", "ModifyObject":
		var raw *schema.GenericObject
		if operation == "CreateObject" {
			var request schema.CreateObjectRequest
			if err := xml.Unmarshal(body, &request); err != nil {
				return failure(err), true
			}
			raw = request.CreateObject
		} else {
			var request schema.ModifyObjectRequest
			if err := xml.Unmarshal(body, &request); err != nil {
				return failure(err), true
			}
			raw = request.ModifyObject
		}
		value, err := DecodeGenericObject(raw)
		if err != nil {
			return failure(err), true
		}
		code := ErrorCodeCreateObject
		if operation == "CreateObject" {
			err = s.objectManager.CreateGenericObject(value)
		} else {
			code = ErrorCodeModifyObject
			err = s.objectManager.ModifyGenericObject(value)
		}
		if err != nil {
			return s.genericOperationError(base, operation, code, err), true
		}
		return s.buildOKResponse(base, operation+"Request"), true
	case "DeleteObject", "GetObject":
		var request schema.GetObjectRequest
		if err := xml.Unmarshal(body, &request); err != nil || request.ObjectId == nil {
			return failure(err), true
		}
		id, err := uuid.Parse(string(*request.ObjectId))
		if err != nil || id == uuid.Nil {
			return failure(err), true
		}
		if operation == "DeleteObject" {
			if err := s.objectManager.DeleteGenericObject(id); err != nil {
				return s.genericOperationError(base, operation, ErrorCodeDeleteObject, err), true
			}
			return s.buildOKResponse(base, "DeleteObjectRequest"), true
		}
		value, err := s.objectManager.GetGenericObject(id)
		if err != nil {
			return s.genericOperationError(base, operation, ErrorCodeGenericError, err), true
		}
		return &schema.GetObjectResponse{X1ResponseMessage: s.responseMessage(base), GenericObjectResponseDetails: genericObjectResponse(value)}, true
	case "ListObjectsOfType", "GetAllGenericObjectDetails":
		var request schema.ListObjectsOfTypeRequest
		if err := xml.Unmarshal(body, &request); err != nil {
			return failure(err), true
		}
		if request.ObjectType != "" && !genericObjectTypePattern.MatchString(request.ObjectType) {
			return failure(errors.New("invalid object type")), true
		}
		if operation == "ListObjectsOfType" && request.ObjectType == "" {
			return failure(errors.New("missing object type")), true
		}
		objects, err := s.objectManager.GetGenericObjects()
		if err != nil {
			return s.genericOperationError(base, operation, ErrorCodeGenericError, err), true
		}
		ids := &schema.ListOfGenericObjectIDs{}
		details := &schema.ListOfGenericObjectResponseDetails{}
		for _, value := range objects {
			typ := IRIRuleObjectType
			if value.Policy != nil {
				typ = IRIPolicyObjectType
			}
			if request.ObjectType != "" && request.ObjectType != typ {
				continue
			}
			id := schema.UUID(value.ID.String())
			ids.ObjectId = append(ids.ObjectId, &id)
			details.GenericObjectResponseDetails = append(details.GenericObjectResponseDetails, genericObjectResponse(value))
		}
		if operation == "ListObjectsOfType" {
			return &schema.ListObjectsOfTypeResponse{X1ResponseMessage: s.responseMessage(base), ListOfObjects: ids}, true
		}
		return &schema.GetAllGenericObjectDetailsResponse{X1ResponseMessage: s.responseMessage(base), ListOfGenericObjectResponseDetails: details}, true
	case "DeleteAllObjects":
		if err := s.objectManager.DeleteAllGenericObjects(); err != nil {
			return s.genericOperationError(base, operation, ErrorCodeDeleteAllObjects, err), true
		}
		return s.buildOKResponse(base, "DeleteAllObjectsRequest"), true
	}
	return s.buildErrorResponse(base, operation, 1080, "unsupported generic object operation"), true
}

// validateGenericRequest rejects duplicate or unknown operation fields before
// encoding/xml can discard them or choose a later occurrence.
func validateGenericRequest(body []byte, operation string) error {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	depth := 0
	counts := map[string]int{}
	allowed := map[string]bool{"admfIdentifier": true, "neIdentifier": true, "messageTimestamp": true, "version": true, "x1TransactionId": true}
	required := ""
	switch operation {
	case "CreateObject":
		required = "createObject"
	case "ModifyObject":
		required = "modifyObject"
	case "DeleteObject", "GetObject":
		required = "objectId"
	case "ListObjectsOfType":
		required = "objectType"
	case "GetAllGenericObjectDetails":
		allowed["objectType"] = true
	}
	if required != "" {
		allowed[required] = true
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 && value.Name.Space != "" && value.Name.Space != etsiX1Namespace {
				return errors.New("unsupported generic request namespace")
			}
			if depth == 2 {
				if !allowed[value.Name.Local] || value.Name.Space != "" && value.Name.Space != etsiX1Namespace {
					return errors.New("unsupported generic request field")
				}
				counts[value.Name.Local]++
				if counts[value.Name.Local] > 1 {
					return errors.New("duplicate generic request field")
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	if required != "" && counts[required] != 1 {
		return errors.New("missing generic request field")
	}
	return nil
}
