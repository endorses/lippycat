//go:build li

package schema

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	X1Namespace         = "http://uri.etsi.org/03221/X1/2017/10"
	XSINamespace        = "http://www.w3.org/2001/XMLSchema-instance"
	IRIPolicyNamespace  = "http://uri.etsi.org/03120/common/2026/01/IRIPolicy"
	IRIAdapterNamespace = "urn:lippycat:li:x1:iri-policy:1"
	DictionaryNamespace = "http://uri.etsi.org/03120/common/2016/02/Common"
)

// Existing X1 transport body limits also bound the normalized representation.
// Compact inputs may exceed these limits after namespace declarations expand.
const (
	MaxRequestXMLBytes  = 10 * 1024 * 1024
	MaxResponseXMLBytes = 1024 * 1024
)

// ErrXMLSizeLimit indicates namespace normalization exceeded its caller's body
// budget. No partial normalized document is returned.
var ErrXMLSizeLimit = errors.New("normalized XML exceeds the body size limit")

type namespaceOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (output *namespaceOutput) Write(data []byte) (int, error) {
	if len(data) > output.limit-output.buffer.Len() {
		return 0, ErrXMLSizeLimit
	}
	return output.buffer.Write(data)
}

// NormalizeNamespaces makes inherited namespace declarations explicit, bounded
// by the established request body limit. Query consumers use the smaller bound
// through NormalizeNamespacesBounded.
func NormalizeNamespaces(data []byte) ([]byte, error) {
	return NormalizeNamespacesBounded(data, MaxRequestXMLBytes)
}

// NormalizeNamespacesBounded preserves QName identity while bounding output
// during XML emission. The budget includes copied default and prefix bindings.
func NormalizeNamespacesBounded(data []byte, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, ErrXMLSizeLimit
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	output := namespaceOutput{limit: maxBytes}
	encoder := xml.NewEncoder(&output)

	scope := map[string]string{"xml": "http://www.w3.org/XML/1998/namespace"}
	changes := []map[string]*string{}
	elementNames := []xml.Name{}
	emittedDefaults := []string{""}
	referenceFields := []int{0}
	roots := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.Directive:
			return nil, errors.New("XML directives are not supported")
		case xml.StartElement:
			if len(changes) == 0 {
				roots++
				if roots > 1 {
					return nil, errors.New("multiple XML document roots")
				}
			}
			if len(changes) >= 128 {
				return nil, errors.New("XML nesting limit exceeded")
			}
			if value.Name.Local == "listOfIRIPolicyReferences" {
				if value.Name.Space != X1Namespace || referenceFields[len(referenceFields)-1] > 0 {
					return nil, errors.New("invalid or duplicate IRI policy reference list")
				}
				referenceFields[len(referenceFields)-1]++
			}
			referenceFields = append(referenceFields, 0)
			undo := map[string]*string{}
			attrs := make([]xml.Attr, 0, len(value.Attr))
			seenAttributes := make(map[xml.Name]struct{}, len(value.Attr))
			for _, attr := range value.Attr {
				if _, seen := seenAttributes[attr.Name]; seen {
					return nil, errors.New("duplicate XML attribute")
				}
				seenAttributes[attr.Name] = struct{}{}
				prefix := ""
				declaration := false
				if attr.Name.Space == "xmlns" {
					prefix = attr.Name.Local
					declaration = true
				} else if attr.Name.Space == "" && attr.Name.Local == "xmlns" {
					declaration = true
				}
				if !declaration {
					attrs = append(attrs, attr)
					continue
				}
				if _, seen := undo[prefix]; seen {
					return nil, errors.New("duplicate XML namespace declaration")
				}
				if previous, exists := scope[prefix]; exists {
					copy := previous
					undo[prefix] = &copy
				} else {
					undo[prefix] = nil
				}
				scope[prefix] = attr.Value
			}
			needed := map[string]string{}
			defaultNeeded := false
			for index, attr := range attrs {
				if attr.Name.Space != "" {
					prefix := availableNamespacePrefix("scopeAttr"+strconv.Itoa(index), scope, needed)
					needed[prefix] = attr.Name.Space
					attrs[index].Name = xml.Name{Local: prefix + ":" + attr.Name.Local}
				}
				if attr.Name.Space == XSINamespace && attr.Name.Local == "type" {
					name, err := resolveQName(attr.Value, scope)
					if err != nil {
						return nil, err
					}
					attrs[index].Value = collapseXMLWhitespace(attr.Value)
					parts := strings.Split(attrs[index].Value, ":")
					if len(parts) == 2 {
						needed[parts[0]] = name.Space
					} else {
						defaultNeeded = true
					}
				}
			}
			// Serialize element names with a prefix, leaving the original default
			// namespace available for unprefixed QName attribute values. Carry that
			// binding only where QName resolution needs it, then reset descendants;
			// an unused inherited namespace must not be copied onto every leaf.
			if value.Name.Space != "" {
				prefix := availableNamespacePrefix("scopeElement", scope, needed)
				needed[prefix] = value.Name.Space
				value.Name = xml.Name{Local: prefix + ":" + value.Name.Local}
			}
			keys := make([]string, 0, len(needed))
			for prefix := range needed {
				keys = append(keys, prefix)
			}
			sort.Strings(keys)
			for _, prefix := range keys {
				attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "xmlns:" + prefix}, Value: needed[prefix]})
			}
			emittedDefault := ""
			if defaultNeeded {
				emittedDefault = scope[""]
			}
			if defaultNeeded || emittedDefault != emittedDefaults[len(emittedDefaults)-1] {
				attrs = append(attrs, xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: emittedDefault})
			}
			emittedDefaults = append(emittedDefaults, emittedDefault)
			value.Attr = attrs
			token = value
			changes = append(changes, undo)
			elementNames = append(elementNames, value.Name)
		case xml.CharData:
			if len(changes) == 0 && strings.TrimSpace(string(value)) != "" {
				return nil, errors.New("unexpected text outside XML document root")
			}
		case xml.EndElement:
			value.Name = elementNames[len(elementNames)-1]
			token = value
			undo := changes[len(changes)-1]
			for prefix, previous := range undo {
				if previous == nil {
					delete(scope, prefix)
				} else {
					scope[prefix] = *previous
				}
			}
			changes = changes[:len(changes)-1]
			elementNames = elementNames[:len(elementNames)-1]
			emittedDefaults = emittedDefaults[:len(emittedDefaults)-1]
			referenceFields = referenceFields[:len(referenceFields)-1]
		}
		if err := encoder.EncodeToken(token); err != nil {
			return nil, err
		}
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	return output.buffer.Bytes(), nil
}

// ResolveType resolves an xsi:type QName using declarations on an element.
func ResolveType(start xml.StartElement) (xml.Name, error) {
	prefixes := map[string]string{"": "", "xml": "http://www.w3.org/XML/1998/namespace"}
	value := ""
	found := false
	seen := make(map[xml.Name]struct{}, len(start.Attr))
	for _, attr := range start.Attr {
		if _, duplicate := seen[attr.Name]; duplicate {
			return xml.Name{}, errors.New("duplicate XML attribute")
		}
		seen[attr.Name] = struct{}{}
		if attr.Name.Space == "xmlns" {
			prefixes[attr.Name.Local] = attr.Value
		}
		if attr.Name.Space == "" && attr.Name.Local == "xmlns" {
			prefixes[""] = attr.Value
		}
		if strings.HasPrefix(attr.Name.Local, "xmlns:") {
			prefixes[strings.TrimPrefix(attr.Name.Local, "xmlns:")] = attr.Value
		}
		if attr.Name.Space == XSINamespace && attr.Name.Local == "type" {
			found = true
			value = attr.Value
		}
	}
	if !found || collapseXMLWhitespace(value) == "" {
		return xml.Name{}, errors.New("missing xsi:type")
	}
	return resolveQName(value, prefixes)
}

func availableNamespacePrefix(base string, scope, needed map[string]string) string {
	for {
		_, original := scope[base]
		_, emitted := needed[base]
		if !original && !emitted {
			return base
		}
		base += "_"
	}
}

// XML Schema QName and integer types use the collapse whitespace facet. Only
// XML whitespace participates; Unicode spacing characters are not separators.
func collapseXMLWhitespace(value string) string {
	return strings.Join(strings.FieldsFunc(value, func(char rune) bool { return char == ' ' || char == '\t' || char == '\r' || char == '\n' }), " ")
}

func resolveQName(value string, prefixes map[string]string) (xml.Name, error) {
	value = collapseXMLWhitespace(value)
	parts := strings.Split(value, ":")
	if len(parts) > 2 || parts[len(parts)-1] == "" || len(parts) == 2 && parts[0] == "" || strings.Contains(value, " ") {
		return xml.Name{}, errors.New("invalid xsi:type")
	}
	prefix := ""
	if len(parts) == 2 {
		prefix = parts[0]
	}
	namespace, bound := prefixes[prefix]
	if prefix != "" && (!bound || namespace == "") {
		return xml.Name{}, errors.New("unbound xsi:type prefix")
	}
	return xml.Name{Space: namespace, Local: parts[len(parts)-1]}, nil
}
