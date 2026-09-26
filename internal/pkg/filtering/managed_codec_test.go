package filtering

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestManagedCodecsPreserveCompleteLegacyFixture(t *testing.T) {
	raw, err := os.ReadFile("../processor/filtering/testdata/legacy_filters.yaml")
	require.NoError(t, err)
	filters, err := UnmarshalManagedYAML(raw)
	require.NoError(t, err)
	require.Len(t, filters, 22)
	before := make(map[string]*management.Filter, len(filters))
	for id, f := range filters {
		before[id] = proto.Clone(f).(*management.Filter)
	}
	for _, codec := range []struct {
		name   string
		encode func(map[string]*management.Filter) ([]byte, error)
		decode func([]byte) (map[string]*management.Filter, error)
	}{{"yaml", MarshalManagedYAML, UnmarshalManagedYAML}, {"encrypted", MarshalEncryptedFilters, UnmarshalEncryptedFilters}} {
		t.Run(codec.name, func(t *testing.T) {
			encoded, err := codec.encode(filters)
			require.NoError(t, err)
			repeated, err := codec.encode(filters)
			require.NoError(t, err)
			require.Equal(t, encoded, repeated)
			recovered, err := codec.decode(encoded)
			require.NoError(t, err)
			require.Len(t, recovered, len(filters))
			for id, original := range before {
				require.True(t, proto.Equal(original, filters[id]), "serialization mutated input")
				require.True(t, proto.Equal(original, recovered[id]), id)
			}
			recovered["fixture-radius-compound"].Radius.Criteria[0].Value = "changed"
			require.True(t, proto.Equal(before["fixture-radius-compound"], filters["fixture-radius-compound"]))
		})
	}
}

func TestManagedYAMLRejectsEntireInvalidSnapshot(t *testing.T) {
	const marker = "SENSITIVE-TARGET-DO-NOT-LOG"
	valid := "filters:\n  - id: good\n    type: sip_user\n    pattern: " + marker + "\n"
	cases := map[string]string{
		"empty": "", "missing root": "{}", "null filters": "filters: null", "null filter": "filters: [null]",
		"unknown root":          valid + "extra: true\n",
		"duplicate root":        valid + "filters: []\n",
		"duplicate field":       valid + "    pattern: other\n",
		"unknown field":         valid + "    " + marker + ": true\n",
		"unknown type":          strings.Replace(valid, "sip_user", marker, 1),
		"numeric type":          strings.Replace(valid, "sip_user", "0", 1),
		"duplicate ID":          valid + "  - id: good\n    type: call_id\n    pattern: other\n",
		"partial success":       valid + "  - id: bad\n    type: sip_user\n",
		"trailing document":     valid + "---\nfilters: []\n",
		"trailing null":         valid + "---\n",
		"anchor":                strings.Replace(valid, "id: good", "id: &id good", 1),
		"alias":                 valid + "  - *missing\n",
		"merge":                 valid + "    <<: {enabled: true}\n",
		"negative revision":     valid + "    revision: -1\n",
		"revision overflow":     valid + "    revision: 18446744073709551616\n",
		"revision float":        valid + "    revision: 1.0\n",
		"revision octal":        valid + "    revision: 010\n",
		"scalar null":           valid + "    description: null\n",
		"bool coercion":         valid + "    enabled: 1\n",
		"unknown tag":           strings.Replace(valid, marker, "!secret "+marker, 1),
		"nested radius unknown": valid + "    radius: {" + marker + ": true}\n",
		"bad syntax":            "filters: [" + marker,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			filters, err := UnmarshalManagedYAML([]byte(data))
			require.ErrorIs(t, err, ErrManagedSnapshot)
			require.Nil(t, filters)
			require.NotContains(t, err.Error(), marker)
		})
	}
}

func TestEncryptedFilterPayloadStrictJSON(t *testing.T) {
	valid := `{"version":1,"filters":[{"id":"x","type":"sip_user","pattern":"PRIVATE"}]}`
	cases := map[string]string{
		"plain yaml":         "filters: []",
		"no version":         `{"filters":[]}`,
		"wrong version":      strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"duplicate version":  strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"duplicate field":    strings.Replace(valid, `"id":"x"`, `"id":"x","id":"y"`, 1),
		"unknown field":      strings.Replace(valid, `"id":"x"`, `"id":"x","PRIVATE":true`, 1),
		"trailing document":  valid + `{}`,
		"trailing garbage":   valid + "PRIVATE",
		"null filter":        `{"version":1,"filters":[null]}`,
		"null filters":       `{"version":1,"filters":null}`,
		"type coercion":      strings.Replace(valid, `"sip_user"`, `0`, 1),
		"revision exponent":  strings.Replace(valid, `"id":"x"`, `"id":"x","revision":1e2`, 1),
		"overflow":           strings.Replace(valid, `"id":"x"`, `"id":"x","revision":18446744073709551616`, 1),
		"nested duplicate":   strings.Replace(valid, `"id":"x"`, `"id":"x","radius":{"scope":{"operator_scope":"a","operator_scope":"b"}}`, 1),
		"unpaired surrogate": strings.Replace(valid, "PRIVATE", `\ud800`, 1),
		"low surrogate":      strings.Replace(valid, "PRIVATE", `\udc00`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			filters, err := UnmarshalEncryptedFilters([]byte(data))
			require.ErrorIs(t, err, ErrManagedSnapshot)
			require.Nil(t, filters)
			require.NotContains(t, err.Error(), "PRIVATE")
		})
	}
	filters, err := UnmarshalEncryptedFilters([]byte(valid))
	require.NoError(t, err)
	require.Equal(t, "PRIVATE", filters["x"].Pattern)
}

func TestManagedCodecBoundsBeforeTypedCollections(t *testing.T) {
	for _, decode := range []func([]byte) (map[string]*management.Filter, error){UnmarshalManagedYAML, UnmarshalEncryptedFilters} {
		_, err := decode(bytes.Repeat([]byte(" "), MaxManagedSnapshotBytes+1))
		require.ErrorIs(t, err, ErrManagedSnapshot)
	}
	// Dense collections, tags, deep flow/block/inline sequence nesting are
	// rejected before yaml.Node allocation. Literal punctuation stays text.
	for _, input := range []string{
		"filters: [" + strings.Repeat("[],", maxManagedSyntaxUnits+1) + "]",
		"filters: !!seq [" + strings.Repeat("[],", maxManagedSyntaxUnits+1) + "]",
		"--- [" + strings.Repeat("[],", maxManagedSyntaxUnits+1) + "]",
		"? [" + strings.Repeat("[],", maxManagedSyntaxUnits+1) + "]\n: value",
		"filters:\n  - description: |1\n     text\n    target_hunters: [" + strings.Repeat("[],", maxManagedSyntaxUnits+1) + "]",
		strings.Repeat("[", maxManagedDepth+1),
		strings.Repeat("- ", maxManagedDepth+1) + "value",
		"filters:\n  - description: literal\n      'not-a-quote\n    target_hunters: [" + strings.Repeat("[],", maxManagedSyntaxUnits+1) + "]\n      closing'",
	} {
		err := managedYAMLSyntaxBudget([]byte(input))
		require.ErrorIs(t, err, ErrManagedSnapshot)
	}
	_, err := UnmarshalManagedYAML([]byte("filters: [" + strings.Repeat("{},", MaxManagedFilters) + "{}]"))
	require.ErrorContains(t, err, "collection limit")
	_, err = UnmarshalEncryptedFilters([]byte(`{"version":1,"filters":[` + strings.Repeat(`{},`, MaxManagedFilters) + `{}]}`))
	// A malformed first entry may fail before the count boundary, but cannot be
	// partially accepted or allocate the declared complete collection.
	require.ErrorIs(t, err, ErrManagedSnapshot)
	valid := &management.Filter{Id: "x", Pattern: "value"}
	valid.TargetHunters = make([]string, maxManagedHunters+1)
	require.ErrorIs(t, ValidateManagedFilter(valid), ErrManagedSnapshot)
	valid.TargetHunters = nil
	valid.Description = strings.Repeat("x", MaxManagedStringBytes+1)
	require.ErrorIs(t, ValidateManagedFilter(valid), ErrManagedSnapshot)
}

func TestManagedYAMLLiteralPunctuationAndCommentsRemainSupported(t *testing.T) {
	// These documents have millions of punctuation bytes but modest syntax.
	filters := make(map[string]*management.Filter)
	for i := 0; i < 400; i++ {
		id := fmt.Sprint(i)
		filters[id] = &management.Filter{Id: id, Pattern: "value", Description: strings.Repeat("[]{},:", 680)}
	}
	raw, err := MarshalManagedYAML(filters)
	require.NoError(t, err)
	decoded, err := UnmarshalManagedYAML(raw)
	require.NoError(t, err)
	require.Len(t, decoded, len(filters))
	for id, filter := range filters {
		require.True(t, proto.Equal(filter, decoded[id]))
	}
	for _, literal := range []string{
		"description: |\n      []{}:, &anchor *alias 'quotes'\n      another line",
		"description: >-\n      []{}:, &anchor *alias 'quotes'\n      another line",
		"description: plain text\n      'literal quote\n      more text'",
		`description: 'single '' quoted []{},:'`,
		`description: "double \" quoted []{},:"`,
	} {
		data := "filters:\n  - id: x\n    type: sip_user\n    pattern: value\n    " + literal + "\n"
		_, err := UnmarshalManagedYAML([]byte(data))
		require.NoError(t, err, literal)
	}
	_, err = UnmarshalManagedYAML([]byte("#" + strings.Repeat("[]{},:", 200_000) + "\nfilters: []\n"))
	require.NoError(t, err)
}

func TestManagedCandidateRejectsLossAndDoesNotMutate(t *testing.T) {
	for _, candidate := range []*management.Filter{
		nil,
		{Id: "x", Type: management.FilterType(999), Pattern: "PRIVATE"},
		{Id: "x", Type: management.FilterType_FILTER_TLS_JA3, Pattern: "PRIVATE"},
		{Id: "x", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "PRIVATE"},
		{Id: "x", Type: management.FilterType_FILTER_RADIUS_COMPOUND, Radius: &management.RadiusFilterCriteria{Criteria: []*management.RadiusCriterion{nil}}},
	} {
		err := ValidateManagedFilter(candidate)
		require.ErrorIs(t, err, ErrManagedSnapshot)
		require.NotContains(t, err.Error(), "PRIVATE")
	}
	f := &management.Filter{Id: "x", Pattern: "+ 1555", Type: management.FilterType_FILTER_PHONE_NUMBER}
	before := proto.Clone(f)
	require.NoError(t, ValidateManagedFilter(f))
	require.True(t, proto.Equal(before, f), "validation must not normalize phone numbers")
	_, err := MarshalManagedYAML(map[string]*management.Filter{"different": f})
	require.ErrorIs(t, err, ErrManagedSnapshot)
	f.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	_, err = MarshalEncryptedFilters(map[string]*management.Filter{"x": f})
	require.ErrorIs(t, err, ErrManagedSnapshot)
}

func TestManagedEmptyAndUint64RoundTrip(t *testing.T) {
	encoded, err := MarshalManagedYAML(nil)
	require.NoError(t, err)
	require.Equal(t, "filters: []\n", string(encoded))
	filters, err := UnmarshalManagedYAML(encoded)
	require.NoError(t, err)
	require.Empty(t, filters)
	encoded, err = MarshalEncryptedFilters(nil)
	require.NoError(t, err)
	require.JSONEq(t, `{"version":1,"filters":[]}`, string(encoded))
	filters, err = UnmarshalEncryptedFilters(encoded)
	require.NoError(t, err)
	require.Empty(t, filters)
	for _, revision := range []uint64{0, 1 << 53, ^uint64(0)} {
		t.Run(fmt.Sprint(revision), func(t *testing.T) {
			f := &management.Filter{Id: "x", Pattern: "value", Revision: revision}
			raw, err := MarshalEncryptedFilters(map[string]*management.Filter{"x": f})
			require.NoError(t, err)
			require.True(t, json.Valid(raw))
			recovered, err := UnmarshalEncryptedFilters(raw)
			require.NoError(t, err)
			require.Equal(t, revision, recovered["x"].Revision)
		})
	}
}

func TestManagedYAMLParserAllocationBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum bounded syntax allocation check")
	}
	// Empty flow mappings maximize Node overhead relative to input bytes. This
	// reaches the preflight budget, then fails the typed filter-count bound.
	raw := []byte("filters: [" + strings.Repeat("{},", (maxManagedDecodeBytes-4096)/(managedSyntaxBytes+12)) + "{}]")
	require.NoError(t, managedYAMLSyntaxBudget(raw))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := UnmarshalManagedYAML(raw)
	runtime.ReadMemStats(&after)
	require.ErrorIs(t, err, ErrManagedSnapshot)
	allocated := after.TotalAlloc - before.TotalAlloc + uint64(len(raw))
	t.Logf("maximum flow-node input+decode allocation: %d bytes", allocated)
	require.LessOrEqual(t, allocated, uint64(256<<20), "input and transient parser allocations exceed the store reservation")
}

func TestManagedYAMLTypedAllocationBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum schema-rich decode allocation check")
	}
	var source strings.Builder
	source.WriteString("filters: [")
	for i := 0; i < 2680; i++ {
		if i != 0 {
			source.WriteByte(',')
		}
		fmt.Fprintf(&source, `{id: "f%d", type: sip_user, pattern: value, target_hunters: [`, i)
		for j := 0; j < maxManagedHunters; j++ {
			if j != 0 {
				source.WriteByte(',')
			}
			source.WriteString(`"hunter-0000"`)
		}
		source.WriteString("]}")
	}
	source.WriteByte(']')
	raw := []byte(source.String())
	source.Reset()
	require.NoError(t, managedYAMLSyntaxBudget(raw))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	filters, err := UnmarshalManagedYAML(raw)
	runtime.ReadMemStats(&after)
	require.NoError(t, err)
	require.Len(t, filters, 2680)
	allocated := after.TotalAlloc - before.TotalAlloc + uint64(len(raw))
	t.Logf("schema-rich input+decode allocation: %d bytes", allocated)
	require.LessOrEqual(t, allocated, uint64(256<<20), "typed candidates and syntax exceed the store reservation")
}

func TestManagedPreflightRejectsOverBudget(t *testing.T) {
	dense := []byte("filters: [" + strings.Repeat("{},", (maxManagedDecodeBytes-4096)/(managedSyntaxBytes+12)+32) + "{}]")
	require.ErrorIs(t, managedYAMLSyntaxBudget(dense), ErrManagedSnapshot)
	var source strings.Builder
	source.WriteString("filters: [")
	for i := 0; i < 2700; i++ {
		if i > 0 {
			source.WriteByte(',')
		}
		fmt.Fprintf(&source, `{id: "f%d", type: sip_user, pattern: value, target_hunters: [`, i)
		source.WriteString(strings.TrimSuffix(strings.Repeat(`"hunter-0000",`, maxManagedHunters), ","))
		source.WriteString("]}")
	}
	source.WriteByte(']')
	require.ErrorIs(t, managedYAMLSyntaxBudget([]byte(source.String())), ErrManagedSnapshot)
}

func TestManagedMaximumOrdinaryFilterCount(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum schema count allocation check")
	}
	var source strings.Builder
	source.WriteString("filters:\n")
	for i := 0; i < MaxManagedFilters; i++ {
		fmt.Fprintf(&source, "  - id: f%d\n    type: sip_user\n    pattern: value\n    enabled: true\n", i)
	}
	raw := []byte(source.String())
	require.NoError(t, managedYAMLSyntaxBudget(raw))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	filters, err := UnmarshalManagedYAML(raw)
	runtime.ReadMemStats(&after)
	require.NoError(t, err)
	require.Len(t, filters, MaxManagedFilters)
	allocated := after.TotalAlloc - before.TotalAlloc + uint64(len(raw))
	t.Logf("maximum ordinary-filter input+decode allocation: %d bytes", allocated)
	require.LessOrEqual(t, allocated, uint64(maxManagedDecodeBytes))
	_, err = MarshalManagedYAML(filters)
	require.NoError(t, err)
}

func TestManagedIPPatternValidation(t *testing.T) {
	for _, pattern := range []string{"192.0.2.1", "192.0.2.1/24", "2001:db8::1", "2001:db8::/32", "192.168.*", "192.168.*.*", "*"} {
		t.Run(pattern, func(t *testing.T) {
			require.NoError(t, ValidateManagedFilter(&management.Filter{Id: "ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: pattern}))
		})
	}
	for _, pattern := range []string{"999.2.3.4", "192.0.2.1/99", "2001:invalid::", "abc.*", "999.*", "1.2.3.4.*", "192..*"} {
		t.Run(pattern, func(t *testing.T) {
			require.ErrorIs(t, ValidateManagedFilter(&management.Filter{Id: "ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: pattern}), ErrManagedSnapshot)
		})
	}
}
