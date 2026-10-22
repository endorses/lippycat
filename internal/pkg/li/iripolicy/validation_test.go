//go:build li

package iripolicy_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
)

func TestProfileDictionaryValidation(t *testing.T) {
	require.NoError(t, iripolicy.ValidateProfile(iripolicy.Profile{}))
	require.NoError(t, iripolicy.ValidateProfile(profile()))
	for _, tc := range []struct {
		name    string
		profile iripolicy.Profile
	}{
		{"invented ETSI NF", iripolicy.Profile{NFTypes: []iripolicy.DictionaryEntry{{Owner: "ETSI", Name: "NFType", Value: "Probe"}}}},
		{"invented ETSI event", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{{Owner: "ETSI", Name: "IRIEvents", Value: "Start"}}}},
		{"vendor owner", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{{Owner: "ExampleVendor", Name: "IRIEvents", Value: "Start"}}}},
		{"lowercase national owner", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{{Owner: "de", Name: "IRIEvents", Value: "Start"}}}},
		{"wrong dictionary", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{{Owner: "DE", Name: "NFType", Value: "Start"}}}},
		{"empty entry", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{{Owner: "DE", Name: "IRIEvents"}}}},
		{"oversized entry", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{{Owner: "DE", Name: "IRIEvents", Value: strings.Repeat("a", 256)}}}},
		{"invalid Unicode entry", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{{Owner: "DE", Name: "IRIEvents", Value: "\xff"}}}},
		{"invalid XML entry", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{{Owner: "DE", Name: "IRIEvents", Value: "\x00"}}}},
		{"invented ETSI handover", iripolicy.Profile{HandoverFormats: []iripolicy.DictionaryEntry{{Owner: "ETSI", Name: "HandoverFormat", Value: "TS103221-2"}}}},
		{"duplicate entry", iripolicy.Profile{Events: []iripolicy.DictionaryEntry{startEvent, startEvent}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, iripolicy.ValidateProfile(tc.profile), iripolicy.ErrInvalidProfile)
		})
	}
	for _, format := range []string{"TS102232-2", "TS102232-3", "TS102232-4", "TS102232-5", "TS102232-6", "TS102232-7", "TS103707", "TS103976"} {
		t.Run(format, func(t *testing.T) {
			entry := iripolicy.DictionaryEntry{Owner: "ETSI", Name: "HandoverFormat", Value: format}
			p := iripolicy.Profile{HandoverFormats: []iripolicy.DictionaryEntry{entry}}
			require.NoError(t, iripolicy.ValidateProfile(p))
			id, objects := policyGraph(iripolicy.Rule{Action: suppressed, Criteria: []iripolicy.Criterion{{HandoverFormat: &entry}}})
			compiled, err := iripolicy.Compile([]uuid.UUID{id}, objects, p, iripolicy.Limits{})
			require.NoError(t, err)
			require.False(t, compiled.Deliver(iripolicy.Facts{HandoverFormat: &entry}))
		})
	}
	// National definitions must be explicitly configured, not merely well formed.
	id, objects := policyGraph(iripolicy.Rule{Action: suppressed, Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{startEvent}}}})
	_, err := iripolicy.Compile([]uuid.UUID{id}, objects, iripolicy.Profile{}, iripolicy.Limits{})
	require.ErrorIs(t, err, iripolicy.ErrUnsupportedEntry)
}

func TestResourceLimits(t *testing.T) {
	id, objects := policyGraph(catchAll(suppressed), catchAll(delivered))
	for _, tc := range []struct {
		name   string
		limits iripolicy.Limits
	}{
		{"objects", iripolicy.Limits{MaxObjects: 2}},
		{"rule references", iripolicy.Limits{MaxRulesPerPolicy: 1}},
		{"negative objects", iripolicy.Limits{MaxObjects: -1}},
		{"negative policy references", iripolicy.Limits{MaxPolicyReferences: -1}},
		{"negative rule references", iripolicy.Limits{MaxRulesPerPolicy: -1}},
		{"negative criteria", iripolicy.Limits{MaxCriteriaPerRule: -1}},
		{"negative entries", iripolicy.Limits{MaxEntriesPerCriterion: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := iripolicy.Compile([]uuid.UUID{id}, objects, profile(), tc.limits)
			if strings.HasPrefix(tc.name, "negative") {
				require.ErrorIs(t, err, iripolicy.ErrInvalidLimits)
			} else {
				require.ErrorIs(t, err, iripolicy.ErrLimitExceeded)
			}
		})
	}
	secondID, secondObjects := policyGraph(catchAll(delivered))
	_, err := iripolicy.Compile([]uuid.UUID{id, secondID}, append(objects, secondObjects...), profile(), iripolicy.Limits{MaxPolicyReferences: 1})
	require.ErrorIs(t, err, iripolicy.ErrLimitExceeded)

	id, objects = policyGraph(iripolicy.Rule{Action: suppressed, Criteria: []iripolicy.Criterion{
		{Events: []iripolicy.DictionaryEntry{startEvent, stopEvent}},
		{NFTypes: []iripolicy.DictionaryEntry{probeNF}},
	}})
	_, err = iripolicy.Compile([]uuid.UUID{id}, objects, profile(), iripolicy.Limits{MaxCriteriaPerRule: 1})
	require.ErrorIs(t, err, iripolicy.ErrLimitExceeded)
	_, err = iripolicy.Compile([]uuid.UUID{id}, objects, profile(), iripolicy.Limits{MaxEntriesPerCriterion: 1})
	require.ErrorIs(t, err, iripolicy.ErrLimitExceeded)

	_, err = iripolicy.Compile([]uuid.UUID{id}, objects, profile(), iripolicy.Limits{MaxObjects: 2, MaxPolicyReferences: 1, MaxRulesPerPolicy: 1, MaxCriteriaPerRule: 2, MaxEntriesPerCriterion: 2})
	require.NoError(t, err, "inclusive limits must accept exactly the configured counts")
}

func TestCompileRequiresCommittedSourceGenerations(t *testing.T) {
	for _, index := range []int{0, 1} {
		id, objects := policyGraph(catchAll(suppressed))
		objects[index].Generation = 0
		require.NoError(t, iripolicy.ValidateObjects(objects, profile(), iripolicy.Limits{}), "precommit definitions can be validated")
		_, err := iripolicy.Compile([]uuid.UUID{id}, objects, profile(), iripolicy.Limits{})
		require.ErrorIs(t, err, iripolicy.ErrInvalidGeneration)
	}
	id, objects := policyGraph(catchAll(suppressed))
	unused := iripolicy.Object{ID: uuid.New(), Rule: &iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{allEvents}}}, Action: delivered}}
	compiled := compile(t, []uuid.UUID{id}, append(objects, unused))
	_, exists := compiled.SourceGenerations()[unused.ID]
	require.False(t, exists, "unreferenced objects are not delivery authority")
}

func TestCloneAndCanonicalDefinitionEquality(t *testing.T) {
	id, objects := policyGraph(iripolicy.Rule{Action: suppressed, Criteria: []iripolicy.Criterion{
		{Events: []iripolicy.DictionaryEntry{startEvent, stopEvent}},
		{NFTypes: []iripolicy.DictionaryEntry{probeNF, edgeNF}},
		{HandoverFormat: &rawFormat},
	}}, catchAll(delivered))
	clones := iripolicy.CloneObjects(objects)
	for i := range objects {
		require.True(t, iripolicy.EqualObjects(objects[i], clones[i]))
		clones[i].Generation++
		require.True(t, iripolicy.EqualObjects(objects[i], clones[i]), "administrative generation is not definition content")
	}
	clones[0].Policy.Rules[0], clones[0].Policy.Rules[1] = clones[0].Policy.Rules[1], clones[0].Policy.Rules[0]
	require.True(t, iripolicy.EqualObjects(objects[0], clones[0]))
	clones[1].Rule.Criteria[0].Events[0], clones[1].Rule.Criteria[0].Events[1] = clones[1].Rule.Criteria[0].Events[1], clones[1].Rule.Criteria[0].Events[0]
	clones[1].Rule.Criteria[0], clones[1].Rule.Criteria[1] = clones[1].Rule.Criteria[1], clones[1].Rule.Criteria[0]
	require.True(t, iripolicy.EqualObjects(objects[1], clones[1]))
	require.Equal(t, startEvent, objects[1].Rule.Criteria[0].Events[0], "canonicalization does not mutate input")
	clones[1].Rule.Criteria[0].NFTypes[0] = otherNF
	require.False(t, iripolicy.EqualObjects(objects[1], clones[1]))
	require.Equal(t, probeNF, objects[1].Rule.Criteria[1].NFTypes[0])
	*clones[1].Rule.Criteria[2].HandoverFormat = otherFormat
	require.Equal(t, rawFormat, *objects[1].Rule.Criteria[2].HandoverFormat)
	clones[0].Policy.Name = "different"
	require.False(t, iripolicy.EqualObjects(objects[0], clones[0]))
	require.Equal(t, id, objects[0].ID)
	require.Nil(t, iripolicy.CloneObjects(nil))
	clones[2].Rule.Criteria = nil
	require.False(t, iripolicy.EqualObjects(objects[2], clones[2]))
	clones[2] = iripolicy.CloneObject(objects[2])
	clones[2].Rule.Action = suppressed
	require.False(t, iripolicy.EqualObjects(objects[2], clones[2]))
	clones[2] = iripolicy.CloneObject(objects[2])
	clones[2].ID = uuid.New()
	require.False(t, iripolicy.EqualObjects(objects[2], clones[2]))
}
