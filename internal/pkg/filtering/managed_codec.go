package filtering

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/endorses/lippycat/api/gen/management"
	"gopkg.in/yaml.v3"
)

const (
	MaxManagedSnapshotBytes = 16 << 20
	MaxManagedFilters       = 65_536
	MaxManagedStringBytes   = 4_096
	maxManagedHunters       = 256
	maxManagedTotalHunters  = 1_048_576
	maxManagedCriteria      = 64
	maxManagedTotalCriteria = 262_144
	// Bound the YAML parser's intermediate tree as well as typed collections.
	maxManagedSyntaxUnits = 1 << 20
	maxManagedYAMLNodes   = 1 << 20
	maxManagedDepth       = 16
	maxManagedDecodeBytes = 256 << 20
	managedSyntaxBytes    = 320
	managedMappingBytes   = 80
)

var ErrManagedSnapshot = errors.New("invalid managed filter snapshot")

func managedError(class string) error { return fmt.Errorf("%w: %s", ErrManagedSnapshot, class) }

type managedDocument struct {
	Version int           `json:"version"`
	Filters []*FilterYAML `json:"filters"`
}

type managedShape struct {
	kind     byte // object, array, string, unsigned integer, boolean
	fields   map[string]*managedShape
	required []string
	item     *managedShape
	limit    int
	count    byte
}

func managedSchema(encrypted bool) *managedShape {
	str, number, boolean := &managedShape{kind: 's'}, &managedShape{kind: 'u'}, &managedShape{kind: 'b'}
	scope := &managedShape{kind: 'o', fields: map[string]*managedShape{
		"operator_scope": str, "profile_revision": str, "origin_node_id": str, "source_id": str,
	}}
	criterion := &managedShape{kind: 'o', fields: map[string]*managedShape{
		"filter_id": str, "filter_revision": number, "kind": str, "value": str, "mac_profile": str, "target_kind": str,
	}}
	radius := &managedShape{kind: 'o', fields: map[string]*managedShape{
		"mac_profile": str, "target_kind": str, "group_id": str, "task_id": str, "task_generation": number, "scope": scope,
		"criteria": {kind: 'a', item: criterion, limit: maxManagedCriteria, count: 'c'},
	}}
	filter := &managedShape{kind: 'o', required: []string{"id", "type"}, fields: map[string]*managedShape{
		"id": str, "type": str, "pattern": str, "revision": number, "enabled": boolean, "description": str, "radius": radius,
		"target_hunters": {kind: 'a', item: str, limit: maxManagedHunters, count: 'h'},
	}}
	root := &managedShape{kind: 'o', required: []string{"filters"}, fields: map[string]*managedShape{
		"filters": {kind: 'a', item: filter, limit: MaxManagedFilters},
	}}
	if encrypted {
		root.fields["version"] = number
		root.required = append(root.required, "version")
	}
	return root
}

type managedCounts struct {
	hunters, criteria, nodes int
	decodeRemaining          int64 // only the explicit shared-budget JSON path
	sharedBudget             bool
}

func (c *managedCounts) chargeDecode(n int64) error {
	if c.sharedBudget {
		if n > c.decodeRemaining {
			return managedError("decode memory limit exceeded")
		}
		c.decodeRemaining -= n
	}
	return nil
}

func (c *managedCounts) add(s *managedShape, n int) error {
	if n > s.limit {
		return managedError("collection limit exceeded")
	}
	switch s.count {
	case 'h':
		if n > maxManagedTotalHunters-c.hunters {
			return managedError("total hunter limit exceeded")
		}
		c.hunters += n
	case 'c':
		if n > maxManagedTotalCriteria-c.criteria {
			return managedError("total criterion limit exceeded")
		}
		c.criteria += n
	}
	return nil
}

func managedInput(data []byte) error {
	if len(data) == 0 || len(data) > MaxManagedSnapshotBytes || !utf8.Valid(data) {
		return managedError("document size or encoding")
	}
	return nil
}

func managedUint(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, b := range []byte(value) {
		if b < '0' || b > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func checkManagedYAML(n *yaml.Node, s *managedShape, c *managedCounts, depth int) error {
	c.nodes++
	if depth > maxManagedDepth || c.nodes > maxManagedYAMLNodes || n.Anchor != "" || n.Kind == yaml.AliasNode {
		return managedError("syntax depth, node, or alias limit")
	}
	switch s.kind {
	case 'o':
		if n.Kind != yaml.MappingNode || n.Tag != "!!map" || len(n.Content)%2 != 0 || len(n.Content)/2 > len(s.fields) {
			return managedError("object schema")
		}
		seen := make(map[string]bool, len(s.fields))
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			child := s.fields[key.Value]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" || child == nil || seen[key.Value] {
				return managedError("unknown or duplicate field")
			}
			seen[key.Value] = true
			if err := checkManagedYAML(n.Content[i+1], child, c, depth+1); err != nil {
				return err
			}
		}
		for _, key := range s.required {
			if !seen[key] {
				return managedError("required field missing")
			}
		}
	case 'a':
		if n.Kind != yaml.SequenceNode || n.Tag != "!!seq" {
			return managedError("array schema")
		}
		if err := c.add(s, len(n.Content)); err != nil {
			return err
		}
		for _, child := range n.Content {
			if err := checkManagedYAML(child, s.item, c, depth+1); err != nil {
				return err
			}
		}
	default:
		if n.Kind != yaml.ScalarNode || len(n.Value) > MaxManagedStringBytes {
			return managedError("scalar schema or size")
		}
		valid := s.kind == 's' && n.Tag == "!!str" || s.kind == 'u' && n.Tag == "!!int" && managedUint(n.Value) ||
			s.kind == 'b' && n.Tag == "!!bool"
		if !valid {
			return managedError("scalar type")
		}
	}
	return nil
}

// UnmarshalManagedYAML is the strict persistence/migration reader. It deliberately
// does not share ParseFileWithErrors' partial-success CLI import behavior.
func UnmarshalManagedYAML(data []byte) (map[string]*management.Filter, error) {
	if err := managedInput(data); err != nil {
		return nil, err
	}
	if err := managedYAMLSyntaxBudget(data); err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return nil, managedError("malformed YAML")
	}
	if err := checkManagedYAML(document.Content[0], managedSchema(false), &managedCounts{}, 0); err != nil {
		return nil, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, managedError("trailing YAML document")
	}
	var config FilterConfig
	if err := document.Decode(&config); err != nil {
		return nil, managedError("invalid YAML fields")
	}
	return managedFilters(config.Filters)
}

func checkManagedJSON(d *json.Decoder, s *managedShape, c *managedCounts, depth int) error {
	if depth > maxManagedDepth {
		return managedError("syntax depth limit")
	}
	// Charge before Token or a typed collection can allocate. Per-object storage
	// includes both FilterYAML and protobuf representations, slice spare capacity,
	// the result-map entry, and bounded validation scratch.
	charge := int64(128)
	if s.kind == 'o' {
		charge += 512
	}
	if err := c.chargeDecode(charge); err != nil {
		return err
	}
	token, err := d.Token()
	if err != nil {
		return managedError("malformed JSON")
	}
	switch s.kind {
	case 'o':
		if token != json.Delim('{') {
			return managedError("object schema")
		}
		seen := make(map[string]bool, len(s.fields))
		for d.More() {
			keyToken, err := d.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] || s.fields[key] == nil {
				return managedError("unknown or duplicate field")
			}
			if err := c.chargeDecode(int64(128 + len(key))); err != nil {
				return err
			}
			seen[key] = true
			if err := checkManagedJSON(d, s.fields[key], c, depth+1); err != nil {
				return err
			}
		}
		for _, key := range s.required {
			if !seen[key] {
				return managedError("required field missing")
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return managedError("object terminator")
		}
	case 'a':
		if token != json.Delim('[') {
			return managedError("array schema")
		}
		count := 0
		for d.More() {
			count++
			if count > s.limit {
				return managedError("collection limit exceeded")
			}
			if err := c.add(s, 1); err != nil {
				return err
			}
			if err := checkManagedJSON(d, s.item, c, depth+1); err != nil {
				return err
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return managedError("array terminator")
		}
	case 's':
		str, ok := token.(string)
		if !ok || len(str) > MaxManagedStringBytes || !utf8.ValidString(str) {
			return managedError("string schema or size")
		}
	case 'u':
		value, ok := token.(json.Number)
		if !ok || !managedUint(string(value)) {
			return managedError("unsigned integer schema")
		}
	case 'b':
		if _, ok := token.(bool); !ok {
			return managedError("boolean schema")
		}
	}
	return nil
}

// UnmarshalEncryptedFilters decodes the versioned plaintext payload AFTER the
// snapshot owner has authenticated its securestore envelope and identity.
func UnmarshalEncryptedFilters(data []byte) (map[string]*management.Filter, error) {
	return unmarshalEncryptedFilters(data, &managedCounts{})
}

// UnmarshalEncryptedFiltersWithBudget validates the entire payload within an
// explicit share of a caller's aggregate memory reservation. It retains the
// ordinary schema and collection limits, but may reject a valid large document
// when the remaining allowance is smaller. Admission charges 64 KiB fixed
// scratch, four source lengths for decoder buffers and decoded strings, 128
// bytes per value, 512 per object, and 128 plus key length per field before
// typed decoding. No intermediate JSON tree is allocated. The source may already
// be charged by the caller; counting it again is deliberately conservative.
func UnmarshalEncryptedFiltersWithBudget(data []byte, remainingDecodeBytes int64) (map[string]*management.Filter, error) {
	if remainingDecodeBytes <= 0 || remainingDecodeBytes > maxManagedDecodeBytes {
		return nil, managedError("decode memory allowance")
	}
	counts := &managedCounts{sharedBudget: true, decodeRemaining: remainingDecodeBytes}
	if err := counts.chargeDecode(64<<10 + 4*int64(len(data))); err != nil {
		return nil, err
	}
	return unmarshalEncryptedFilters(data, counts)
}

func unmarshalEncryptedFilters(data []byte, counts *managedCounts) (map[string]*management.Filter, error) {
	if err := managedInput(data); err != nil {
		return nil, err
	}
	if !managedJSONUnicode(data) {
		return nil, managedError("invalid Unicode escape")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := checkManagedJSON(decoder, managedSchema(true), counts, 0); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, managedError("trailing JSON document")
	}
	var doc managedDocument
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != 1 {
		return nil, managedError("unsupported payload version or fields")
	}
	return managedFilters(doc.Filters)
}

// encoding/json replaces unpaired UTF-16 surrogates instead of returning an
// error. Managed persistence must reject that lossy identity conversion.
func managedJSONUnicode(data []byte) bool {
	quoted := false
	for i := 0; i < len(data); {
		if data[i] == '"' {
			quoted = !quoted
			i++
			continue
		}
		if !quoted || data[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(data) {
			return false
		}
		if data[i+1] != 'u' {
			i += 2
			continue
		}
		if i+6 > len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil || value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+12 > len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
		i += 6
	}
	return true
}

func managedFilters(entries []*FilterYAML) (map[string]*management.Filter, error) {
	filters := make(map[string]*management.Filter, len(entries))
	for _, entry := range entries {
		filter, err := YAMLToProto(entry)
		if err != nil {
			return nil, managedError("invalid filter definition")
		}
		if !IsRADIUSFilter(filter.Type) {
			if err := validateManagedPattern(filter.Type, filter.Pattern); err != nil {
				return nil, managedError("invalid filter pattern")
			}
		}
		if _, found := filters[filter.Id]; found {
			return nil, managedError("duplicate filter ID")
		}
		filters[filter.Id] = filter
	}
	return filters, nil
}

func managedStrings(values ...string) error {
	for _, value := range values {
		if len(value) > MaxManagedStringBytes || !utf8.ValidString(value) {
			return managedError("string size or encoding")
		}
	}
	return nil
}

func validateManagedPattern(kind management.FilterType, pattern string) error {
	if err := ValidatePattern(kind, pattern); err != nil {
		return managedError("invalid filter pattern")
	}
	if kind != management.FilterType_FILTER_IP_ADDRESS {
		return nil
	}
	value := strings.TrimSpace(pattern)
	if strings.Contains(value, "*") {
		parts := strings.Split(value, ".")
		if len(parts) > 4 {
			return managedError("invalid IP pattern")
		}
		for _, part := range parts {
			if part == "*" {
				continue
			}
			if !managedUint(part) {
				return managedError("invalid IP pattern")
			}
			n, err := strconv.ParseUint(part, 10, 8)
			if err != nil || n > 255 {
				return managedError("invalid IP pattern")
			}
		}
		return nil
	}
	if strings.Contains(value, "/") {
		if _, err := netip.ParsePrefix(value); err != nil {
			return managedError("invalid IP pattern")
		}
		return nil
	}
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		return managedError("invalid IP pattern")
	}
	return nil
}

// ValidateManagedFilter checks a detached manager candidate without changing
// caller-owned values. Snapshot-wide counts remain the serializer's boundary.
func ValidateManagedFilter(filter *management.Filter) error {
	if filter == nil {
		return managedError("filter is required")
	}
	_, err := managedCandidate(map[string]*management.Filter{filter.Id: filter})
	return err
}

func managedCandidate(filters map[string]*management.Filter) ([]*FilterYAML, error) {
	if len(filters) > MaxManagedFilters {
		return nil, managedError("filter count limit exceeded")
	}
	counts := managedCounts{}
	ids := make([]string, 0, len(filters))
	for id, f := range filters {
		if f == nil || id != f.Id || FilterTypeToString(f.Type) == "unknown" || len(f.ProtoReflect().GetUnknown()) != 0 {
			return nil, managedError("invalid filter identity or type")
		}
		if err := managedStrings(f.Id, f.Pattern, f.Description); err != nil {
			return nil, err
		}
		if err := counts.add(&managedShape{count: 'h', limit: maxManagedHunters}, len(f.TargetHunters)); err != nil {
			return nil, err
		}
		if err := managedStrings(f.TargetHunters...); err != nil {
			return nil, err
		}
		if r := f.Radius; r != nil {
			if len(r.ProtoReflect().GetUnknown()) != 0 {
				return nil, managedError("unknown RADIUS data")
			}
			if err := managedStrings(r.MacProfile, r.TargetKind, r.GroupId, r.TaskId); err != nil {
				return nil, err
			}
			if s := r.Scope; s != nil {
				if len(s.ProtoReflect().GetUnknown()) != 0 {
					return nil, managedError("unknown scope data")
				}
				if err := managedStrings(s.OperatorScope, s.ProfileRevision, s.OriginNodeId, s.SourceId); err != nil {
					return nil, err
				}
			}
			if err := counts.add(&managedShape{count: 'c', limit: maxManagedCriteria}, len(r.Criteria)); err != nil {
				return nil, err
			}
			for _, c := range r.Criteria {
				if c == nil || len(c.ProtoReflect().GetUnknown()) != 0 {
					return nil, managedError("invalid criterion")
				}
				if err := managedStrings(c.FilterId, c.Kind, c.Value, c.MacProfile, c.TargetKind); err != nil {
					return nil, err
				}
			}
		}
		if err := ValidateFilter(f); err != nil {
			return nil, managedError("invalid filter definition")
		}
		if !IsRADIUSFilter(f.Type) {
			if err := validateManagedPattern(f.Type, f.Pattern); err != nil {
				return nil, managedError("invalid filter pattern")
			}
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	entries := make([]*FilterYAML, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, ProtoToYAML(filters[id]))
	}
	return entries, nil
}

type managedBuffer struct{ bytes.Buffer }

func (b *managedBuffer) Write(p []byte) (int, error) {
	if len(p) > MaxManagedSnapshotBytes-b.Len() {
		return 0, managedError("encoded document limit exceeded")
	}
	return b.Buffer.Write(p)
}

// MarshalManagedYAML preserves the editable persistence schema and emits a
// deterministic complete snapshot without normalizing or mutating caller data.
func MarshalManagedYAML(filters map[string]*management.Filter) ([]byte, error) {
	entries, err := managedCandidate(filters)
	if err != nil {
		return nil, err
	}
	var output managedBuffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	err = encoder.Encode(FilterConfig{Filters: entries})
	err = errors.Join(err, encoder.Close())
	if err != nil {
		return nil, managedError("encode YAML snapshot")
	}
	if err := managedYAMLSyntaxBudget(output.Bytes()); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// MarshalEncryptedFilters returns only the versioned JSON payload; encryption
// and durable replacement belong to the snapshot owner.
func MarshalEncryptedFilters(filters map[string]*management.Filter) ([]byte, error) {
	entries, err := managedCandidate(filters)
	if err != nil {
		return nil, err
	}
	var output managedBuffer
	if _, err := output.Write([]byte(`{"version":1,"filters":[`)); err != nil {
		return nil, err
	}
	for i, entry := range entries {
		if i != 0 {
			if _, err := output.Write([]byte(",")); err != nil {
				return nil, err
			}
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return nil, managedError("encode JSON snapshot")
		}
		if _, err := output.Write(data); err != nil {
			return nil, err
		}
	}
	if _, err := output.Write([]byte("]}")); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
