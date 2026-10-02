//go:build li

package x1

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

// A transport success is not an ADMF acknowledgment. Correlate exactly one
// typed response to this attempt before recording successful notification.
func validateReportAcknowledgment(request, response []byte, requestType string) error {
	var sent struct {
		Message schema.X1RequestMessage `xml:"x1RequestMessage"`
	}
	if err := xml.Unmarshal(request, &sent); err != nil {
		return fmt.Errorf("parse sent X1 request: %w", err)
	}
	var envelope struct {
		XMLName  xml.Name
		Attrs    []xml.Attr `xml:",any,attr"`
		Messages []struct {
			XMLName xml.Name
			Attrs   []xml.Attr `xml:",any,attr"`
			schema.X1ResponseMessage
			OK                 []string                 `xml:"oK"`
			RequestMessageType string                   `xml:"requestMessageType"`
			ErrorInformation   *schema.ErrorInformation `xml:"errorInformation"`
		} `xml:"x1ResponseMessage"`
	}
	if err := xml.Unmarshal(response, &envelope); err != nil {
		return fmt.Errorf("parse X1 acknowledgment: %w", err)
	}
	if envelope.XMLName != (xml.Name{Space: etsiX1Namespace, Local: "X1Response"}) || len(envelope.Messages) != 1 {
		return fmt.Errorf("invalid X1 acknowledgment envelope")
	}
	message := envelope.Messages[0]
	if message.XMLName.Space != etsiX1Namespace {
		return fmt.Errorf("invalid X1 acknowledgment namespace")
	}
	responseType := ""
	for _, attr := range message.Attrs {
		if attr.Name == (xml.Name{Space: "http://www.w3.org/2001/XMLSchema-instance", Local: "type"}) {
			responseType = attr.Value
		}
	}
	prefix := ""
	if parts := strings.Split(responseType, ":"); len(parts) == 2 {
		prefix = parts[0]
	} else if len(parts) != 1 {
		return fmt.Errorf("invalid X1 acknowledgment type")
	}
	namespace := ""
	for _, attrs := range [][]xml.Attr{envelope.Attrs, message.Attrs} {
		for _, attr := range attrs {
			if (prefix == "" && attr.Name.Local == "xmlns" && attr.Name.Space == "") || (prefix != "" && attr.Name.Space == "xmlns" && attr.Name.Local == prefix) {
				namespace = attr.Value
			}
		}
	}
	if namespace != etsiX1Namespace {
		return fmt.Errorf("invalid X1 acknowledgment type namespace")
	}
	expected := strings.TrimSuffix(requestType, "Request") + "Response"
	responseType = localXMLName(responseType)
	if responseType != expected && responseType != "ErrorResponse" {
		return fmt.Errorf("unexpected X1 acknowledgment type %q", responseType)
	}
	if err := validateAcknowledgmentFields(response, responseType == "ErrorResponse"); err != nil {
		return err
	}
	base := message.X1ResponseMessage
	if base.X1TransactionId == nil || sent.Message.X1TransactionId == nil || *base.X1TransactionId != *sent.Message.X1TransactionId ||
		base.AdmfIdentifier != sent.Message.AdmfIdentifier || base.NeIdentifier != sent.Message.NeIdentifier || base.Version != sent.Message.Version {
		return fmt.Errorf("X1 acknowledgment does not match request metadata")
	}
	if base.MessageTimestamp == nil {
		return fmt.Errorf("X1 acknowledgment missing timestamp")
	}
	if _, err := time.Parse(qualifiedMicrosecondLayout, string(*base.MessageTimestamp)); err != nil {
		return fmt.Errorf("invalid X1 acknowledgment timestamp: %w", err)
	}
	if responseType == "ErrorResponse" {
		if message.ErrorInformation == nil || message.RequestMessageType != strings.TrimSuffix(requestType, "Request") || len(message.OK) != 0 {
			return fmt.Errorf("invalid X1 error acknowledgment")
		}
		return &ADMFError{ErrorCode: message.ErrorInformation.ErrorCode, ErrorDescription: message.ErrorInformation.ErrorDescription, RequestMessageType: message.RequestMessageType}
	}
	if message.ErrorInformation != nil || len(message.OK) != 1 || (message.OK[0] != "AcknowledgedAndCompleted" && (requestType == "ReportNEIssueRequest" || message.OK[0] != "Acknowledged")) {
		return fmt.Errorf("X1 response did not acknowledge the request")
	}
	return nil
}

// encoding/xml normally ignores unknown namespaces, duplicate fields, and
// element order. Do not let that permissiveness turn malformed XML into a
// successful acknowledgment. Error details cannot establish success.
func validateAcknowledgmentFields(document []byte, isError bool) error {
	expected := []string{"admfIdentifier", "neIdentifier", "messageTimestamp", "version", "x1TransactionId", "oK"}
	if isError {
		expected = append(expected[:5], "requestMessageType", "errorInformation")
	}
	decoder := xml.NewDecoder(bytes.NewReader(document))
	depth, fields, roots, messages := 0, 0, 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("parse acknowledgment structure: %w", err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			switch depth {
			case 1:
				roots++
			case 2:
				messages++
				if element.Name != (xml.Name{Space: etsiX1Namespace, Local: "x1ResponseMessage"}) {
					return fmt.Errorf("unexpected acknowledgment message")
				}
			case 3:
				if fields == len(expected) && isError && element.Name == (xml.Name{Space: etsiX1Namespace, Local: "extensionInformation"}) {
					fields++
					continue
				}
				if fields >= len(expected) || element.Name != (xml.Name{Space: etsiX1Namespace, Local: expected[fields]}) {
					return fmt.Errorf("unexpected or missing acknowledgment field")
				}
				fields++
			default:
				if !isError || fields < 7 {
					return fmt.Errorf("nested acknowledgment field")
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth < 3 && strings.TrimSpace(string(element)) != "" {
				return fmt.Errorf("unexpected acknowledgment text")
			}
		}
	}
	if roots != 1 || messages != 1 || fields < len(expected) {
		return fmt.Errorf("incomplete acknowledgment structure")
	}
	return nil
}
