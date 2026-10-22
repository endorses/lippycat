//go:build li

package schema

import (
	"encoding/xml"
	"errors"
	"strings"
)

// UnmarshalXML rejects malformed reference lists rather than silently treating
// unsupported children as an empty policy list (which would broaden delivery).
func (list *ListOfIRIPolicyReferences) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Space != "xmlns" && attr.Name.Local != "xmlns" && !strings.HasPrefix(attr.Name.Local, "xmlns:") {
			return errors.New("unsupported IRI policy reference attribute")
		}
	}
	if start.Name.Space != X1Namespace {
		return errors.New("invalid IRI policy reference namespace")
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Space != X1Namespace || value.Name.Local != "iRIPolicyReference" {
				return errors.New("unsupported IRI policy reference field")
			}
			if len(list.IRIPolicyReference) >= 256 {
				return errors.New("IRI policy reference limit exceeded")
			}
			node, err := readPolicyXML(decoder, value, 0)
			if err != nil {
				return err
			}
			referenceText, err := scalar(node)
			if err != nil {
				return err
			}
			if _, err := policyUUID(referenceText); err != nil {
				return err
			}
			reference := UUID(referenceText)
			list.IRIPolicyReference = append(list.IRIPolicyReference, &reference)
		case xml.EndElement:
			return nil
		case xml.CharData:
			if strings.TrimSpace(string(value)) != "" {
				return errors.New("unexpected IRI policy reference text")
			}
		case xml.Comment, xml.ProcInst:
			continue
		default:
			return errors.New("unsupported IRI policy reference content")
		}
	}
}
