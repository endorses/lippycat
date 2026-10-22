//go:build li

package schema

import (
	"encoding/xml"
	"errors"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/google/uuid"
)

type policyXMLNode struct {
	Name     xml.Name
	Attr     []xml.Attr
	Text     string
	Children []policyXMLNode
}

func readPolicyXML(decoder *xml.Decoder, start xml.StartElement, depth int) (policyXMLNode, error) {
	node := policyXMLNode{Name: start.Name, Attr: start.Attr}
	for _, attr := range start.Attr {
		if attr.Name.Space == "xmlns" || attr.Name.Local == "xmlns" || strings.HasPrefix(attr.Name.Local, "xmlns:") {
			continue
		}
		if depth == 0 && attr.Name.Space == XSINamespace && attr.Name.Local == "type" {
			continue
		}
		return node, errors.New("unsupported IRI object attribute")
	}
	if depth > 128 {
		return node, errors.New("XML nesting limit exceeded")
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return node, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			child, err := readPolicyXML(decoder, value, depth+1)
			if err != nil {
				return node, err
			}
			node.Children = append(node.Children, child)
		case xml.CharData:
			node.Text += string(value)
		case xml.EndElement:
			return node, nil
		case xml.Directive:
			return node, errors.New("XML directives are not supported")
		}
	}
}

func (n policyXMLNode) children(namespace string, names ...string) (map[string][]policyXMLNode, error) {
	if strings.TrimSpace(n.Text) != "" {
		return nil, errors.New("unexpected IRI object text")
	}
	result := map[string][]policyXMLNode{}
	lastPosition := -1
	for _, child := range n.Children {
		position := -1
		for index, name := range names {
			if child.Name.Local == name {
				position = index
				break
			}
		}
		if position < lastPosition {
			return nil, errors.New("IRI object fields are out of order")
		}
		lastPosition = position
		allowed := false
		for _, name := range names {
			if child.Name.Space == namespace && child.Name.Local == name {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errors.New("unsupported IRI object field")
		}
		result[child.Name.Local] = append(result[child.Name.Local], child)
	}
	return result, nil
}
func one(nodes []policyXMLNode, required bool) (policyXMLNode, error) {
	if len(nodes) > 1 || required && len(nodes) != 1 {
		return policyXMLNode{}, errors.New("missing or duplicate IRI object field")
	}
	if len(nodes) == 0 {
		return policyXMLNode{}, nil
	}
	return nodes[0], nil
}
func textNode(n policyXMLNode) (string, error) {
	if len(n.Children) > 0 || len(n.Attr) > 0 {
		return "", errors.New("invalid IRI scalar field")
	}
	return n.Text, nil
}
func scalar(n policyXMLNode) (string, error) { // Namespace declarations are serialization scope, not attributes of the value.
	attrs := n.Attr[:0]
	for _, a := range n.Attr {
		if a.Name.Space != "xmlns" && a.Name.Local != "xmlns" && !strings.HasPrefix(a.Name.Local, "xmlns:") {
			attrs = append(attrs, a)
		}
	}
	n.Attr = attrs
	return textNode(n)
}
func dictionary(n policyXMLNode) (iripolicy.DictionaryEntry, error) {
	var entry iripolicy.DictionaryEntry
	fields, err := n.children(DictionaryNamespace, "Owner", "Name", "Value")
	if err != nil {
		return entry, err
	}
	values := []*string{&entry.Owner, &entry.Name, &entry.Value}
	for i, name := range []string{"Owner", "Name", "Value"} {
		child, err := one(fields[name], true)
		if err != nil {
			return entry, err
		}
		*values[i], err = scalar(child)
		if err != nil {
			return entry, err
		}
	}
	return entry, nil
}

// UnmarshalXML decodes the project-owned X1 adapter, preserving the official
// TS 103 120 group namespaces and rejecting unsupported derived objects.
func (object *GenericObject) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	typ, err := ResolveType(start)
	if err != nil {
		return err
	}
	if typ.Space != IRIAdapterNamespace || (typ.Local != "IRIPolicyObject" && typ.Local != "IRIRuleObject") {
		return errors.New("unsupported generic object type")
	}
	node, err := readPolicyXML(decoder, start, 0)
	if err != nil {
		return err
	}
	value := iripolicy.Object{}
	var fields = map[string][]policyXMLNode{}
	lastPosition := -1
	for _, child := range node.Children {
		positions := map[string]int{"objectId": 0, "IRIPolicyName": 1, "IRIRules": 2}
		if typ.Local == "IRIRuleObject" {
			positions = map[string]int{"objectId": 0, "Criteria": 1, "Action": 2, "Parameters": 3}
		}
		position, known := positions[child.Name.Local]
		if !known || position < lastPosition {
			return errors.New("unsupported or out-of-order generic object field")
		}
		lastPosition = position
		if child.Name.Space == X1Namespace && child.Name.Local == "objectId" {
			fields["objectId"] = append(fields["objectId"], child)
			continue
		}
		if child.Name.Space != IRIPolicyNamespace {
			return errors.New("unsupported generic object field namespace")
		}
		fields[child.Name.Local] = append(fields[child.Name.Local], child)
	}
	if strings.TrimSpace(node.Text) != "" {
		return errors.New("unexpected generic object text")
	}
	idNode, err := one(fields["objectId"], true)
	if err != nil {
		return err
	}
	id, err := scalar(idNode)
	if err != nil {
		return err
	}
	value.ID, err = policyUUID(id)
	if err != nil || value.ID == uuid.Nil {
		return errors.New("invalid generic object identifier")
	}
	objectID := UUID(value.ID.String())
	object.ObjectId = &objectID
	delete(fields, "objectId")
	if typ.Local == "IRIPolicyObject" {
		for name := range fields {
			if name != "IRIPolicyName" && name != "IRIRules" {
				return errors.New("unsupported IRI policy field")
			}
		}
		policy := &iripolicy.Policy{}
		name, err := one(fields["IRIPolicyName"], false)
		if err != nil {
			return err
		}
		if name.Name.Local != "" {
			policy.Name, err = scalar(name)
			if err != nil {
				return err
			}
		}
		rules, err := one(fields["IRIRules"], true)
		if err != nil {
			return err
		}
		refs, err := rules.children(IRIPolicyNamespace, "IRIRuleReference")
		if err != nil {
			return err
		}
		for _, ref := range refs["IRIRuleReference"] {
			parts, err := ref.children(IRIPolicyNamespace, "Order", "ObjectIdentifier")
			if err != nil {
				return err
			}
			order, err := one(parts["Order"], true)
			if err != nil {
				return err
			}
			orderText, err := scalar(order)
			if err != nil {
				return err
			}
			number, err := parseIRIRuleOrder(orderText)
			if err != nil {
				return err
			}
			target, err := one(parts["ObjectIdentifier"], true)
			if err != nil {
				return err
			}
			targetText, err := scalar(target)
			if err != nil {
				return err
			}
			targetID, err := policyUUID(targetText)
			if err != nil || targetID == uuid.Nil {
				return errors.New("invalid IRI rule reference")
			}
			policy.Rules = append(policy.Rules, iripolicy.RuleReference{Order: number, ObjectID: targetID})
		}
		if len(policy.Rules) == 0 {
			return errors.New("empty IRI policy")
		}
		value.Policy = policy
	} else {
		for name := range fields {
			if name != "Criteria" && name != "Action" && name != "Parameters" {
				return errors.New("unsupported IRI rule field")
			}
		}
		action, err := one(fields["Action"], true)
		if err != nil {
			return err
		}
		rule := &iripolicy.Rule{}
		rule.Action, err = dictionary(action)
		if err != nil {
			return err
		}
		params, err := one(fields["Parameters"], false)
		if err != nil {
			return err
		}
		if len(params.Children) > 0 || strings.TrimSpace(params.Text) != "" {
			return errors.New("unsupported IRI action parameters")
		}
		criteria, err := one(fields["Criteria"], true)
		if err != nil {
			return err
		}
		criteriaFields, err := criteria.children(IRIPolicyNamespace, "Criteria")
		if err != nil {
			return err
		}
		for _, entry := range criteriaFields["Criteria"] {
			kinds, err := entry.children(IRIPolicyNamespace, "NFTypeCriteria", "IRIEventCriteria", "HandoverFormatCriteria")
			if err != nil {
				return err
			}
			if len(entry.Children) != 1 {
				return errors.New("invalid IRI criterion choice")
			}
			criterion := iripolicy.Criterion{}
			for kind, nodes := range kinds {
				child, err := one(nodes, true)
				if err != nil {
					return err
				}
				name := "NFType"
				if kind == "IRIEventCriteria" {
					name = "IRIEvents"
				}
				if kind == "HandoverFormatCriteria" {
					name = "HandoverFormats"
				}
				entries, err := child.children(IRIPolicyNamespace, name)
				if err != nil {
					return err
				}
				if len(entries[name]) == 0 {
					return errors.New("empty IRI criterion")
				}
				for _, item := range entries[name] {
					entry, err := dictionary(item)
					if err != nil {
						return err
					}
					switch kind {
					case "NFTypeCriteria":
						criterion.NFTypes = append(criterion.NFTypes, entry)
					case "IRIEventCriteria":
						criterion.Events = append(criterion.Events, entry)
					case "HandoverFormatCriteria":
						if criterion.HandoverFormat != nil {
							return errors.New("duplicate handover format")
						}
						criterion.HandoverFormat = &entry
					}
				}
			}
			rule.Criteria = append(rule.Criteria, criterion)
		}
		if len(rule.Criteria) == 0 {
			return errors.New("empty IRI rule criteria")
		}
		value.Rule = rule
	}
	object.IRIObject = &value
	return nil
}

func encodePolicyElement(encoder *xml.Encoder, namespace, name string, value any) error {
	return encoder.EncodeElement(value, xml.StartElement{Name: xml.Name{Space: namespace, Local: name}})
}
func encodeDictionary(encoder *xml.Encoder, name string, entry iripolicy.DictionaryEntry) error {
	start := xml.StartElement{Name: xml.Name{Space: IRIPolicyNamespace, Local: name}}
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	for _, field := range []struct{ name, value string }{{"Owner", entry.Owner}, {"Name", entry.Name}, {"Value", entry.Value}} {
		if err := encodePolicyElement(encoder, DictionaryNamespace, field.name, field.value); err != nil {
			return err
		}
	}
	return encoder.EncodeToken(start.End())
}

// MarshalXML emits the agreed deployment adapter type with explicit namespaces.
func (object GenericObject) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	if object.IRIObject == nil {
		return errors.New("generic object has no supported derived value")
	}
	value := object.IRIObject
	kind := "IRIPolicyObject"
	if value.Policy == nil {
		kind = "IRIRuleObject"
	}
	if (value.Policy == nil) == (value.Rule == nil) {
		return errors.New("invalid generic object kind")
	}
	start.Name.Space = X1Namespace
	start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "xmlns:iriAdapter"}, Value: IRIAdapterNamespace}, xml.Attr{Name: xml.Name{Local: "xmlns:xsi"}, Value: XSINamespace}, xml.Attr{Name: xml.Name{Local: "xsi:type"}, Value: "iriAdapter:" + kind})
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	if err := encodePolicyElement(encoder, X1Namespace, "objectId", value.ID.String()); err != nil {
		return err
	}
	if policy := value.Policy; policy != nil {
		if policy.Name != "" {
			if err := encodePolicyElement(encoder, IRIPolicyNamespace, "IRIPolicyName", policy.Name); err != nil {
				return err
			}
		}
		rules := xml.StartElement{Name: xml.Name{Space: IRIPolicyNamespace, Local: "IRIRules"}}
		if err := encoder.EncodeToken(rules); err != nil {
			return err
		}
		for _, reference := range policy.Rules {
			ref := xml.StartElement{Name: xml.Name{Space: IRIPolicyNamespace, Local: "IRIRuleReference"}}
			if err := encoder.EncodeToken(ref); err != nil {
				return err
			}
			if err := encodePolicyElement(encoder, IRIPolicyNamespace, "Order", reference.Order); err != nil {
				return err
			}
			if err := encodePolicyElement(encoder, IRIPolicyNamespace, "ObjectIdentifier", reference.ObjectID.String()); err != nil {
				return err
			}
			if err := encoder.EncodeToken(ref.End()); err != nil {
				return err
			}
		}
		if err := encoder.EncodeToken(rules.End()); err != nil {
			return err
		}
	} else {
		rule := value.Rule
		criteria := xml.StartElement{Name: xml.Name{Space: IRIPolicyNamespace, Local: "Criteria"}}
		if err := encoder.EncodeToken(criteria); err != nil {
			return err
		}
		for _, criterion := range rule.Criteria {
			if err := encoder.EncodeToken(criteria); err != nil {
				return err
			}
			kind, name := "NFTypeCriteria", "NFType"
			entries := criterion.NFTypes
			if criterion.Events != nil {
				kind, name, entries = "IRIEventCriteria", "IRIEvents", criterion.Events
			}
			if criterion.HandoverFormat != nil {
				kind, name, entries = "HandoverFormatCriteria", "HandoverFormats", []iripolicy.DictionaryEntry{*criterion.HandoverFormat}
			}
			choice := xml.StartElement{Name: xml.Name{Space: IRIPolicyNamespace, Local: kind}}
			if err := encoder.EncodeToken(choice); err != nil {
				return err
			}
			for _, entry := range entries {
				if err := encodeDictionary(encoder, name, entry); err != nil {
					return err
				}
			}
			if err := encoder.EncodeToken(choice.End()); err != nil {
				return err
			}
			if err := encoder.EncodeToken(criteria.End()); err != nil {
				return err
			}
		}
		if err := encoder.EncodeToken(criteria.End()); err != nil {
			return err
		}
		if err := encodeDictionary(encoder, "Action", rule.Action); err != nil {
			return err
		}
	}
	return encoder.EncodeToken(start.End())
}

func policyUUID(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || len(value) != 36 || !strings.EqualFold(id.String(), value) {
		return uuid.Nil, errors.New("invalid IRI object UUID")
	}
	return id, nil
}

func parseIRIRuleOrder(value string) (uint64, error) {
	value = collapseXMLWhitespace(value)
	value = strings.TrimPrefix(value, "+")
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || number == 0 {
		return 0, errors.New("invalid IRI rule order")
	}
	return number, nil
}
