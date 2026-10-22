//go:build li

package iripolicy_test

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
)

var (
	allEvents   = iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIEvents", Value: "All"}
	delivered   = iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: "Delivered"}
	suppressed  = iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: "NotDelivered"}
	startEvent  = iripolicy.DictionaryEntry{Owner: "DE", Name: "IRIEvents", Value: "Start"}
	stopEvent   = iripolicy.DictionaryEntry{Owner: "DE", Name: "IRIEvents", Value: "Stop"}
	otherEvent  = iripolicy.DictionaryEntry{Owner: "DE", Name: "IRIEvents", Value: "Other"}
	probeNF     = iripolicy.DictionaryEntry{Owner: "DE", Name: "NFType", Value: "Probe"}
	edgeNF      = iripolicy.DictionaryEntry{Owner: "DE", Name: "NFType", Value: "Edge"}
	otherNF     = iripolicy.DictionaryEntry{Owner: "DE", Name: "NFType", Value: "Other"}
	rawFormat   = iripolicy.DictionaryEntry{Owner: "DE", Name: "HandoverFormat", Value: "RawX2"}
	otherFormat = iripolicy.DictionaryEntry{Owner: "DE", Name: "HandoverFormat", Value: "Other"}
)

func catchAll(action iripolicy.DictionaryEntry) iripolicy.Rule {
	return iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{allEvents}}}, Action: action}
}

func profile() iripolicy.Profile {
	return iripolicy.Profile{
		NFTypes:         []iripolicy.DictionaryEntry{probeNF, edgeNF, otherNF},
		Events:          []iripolicy.DictionaryEntry{startEvent, stopEvent, otherEvent},
		HandoverFormats: []iripolicy.DictionaryEntry{rawFormat, otherFormat},
	}
}

func policyGraph(rules ...iripolicy.Rule) (uuid.UUID, []iripolicy.Object) {
	id := uuid.New()
	policy := iripolicy.Object{ID: id, Generation: 3, Policy: &iripolicy.Policy{Name: "test policy"}}
	objects := make([]iripolicy.Object, 0, len(rules)+1)
	for i, rule := range rules {
		ruleID := uuid.New()
		policy.Policy.Rules = append(policy.Policy.Rules, iripolicy.RuleReference{Order: uint64(i + 1), ObjectID: ruleID})
		ruleCopy := rule
		objects = append(objects, iripolicy.Object{ID: ruleID, Generation: uint64(i + 5), Rule: &ruleCopy})
	}
	return id, append([]iripolicy.Object{policy}, objects...)
}

func compile(t *testing.T, ids []uuid.UUID, objects []iripolicy.Object) *iripolicy.Compiled {
	t.Helper()
	compiled, err := iripolicy.Compile(ids, objects, profile(), iripolicy.Limits{})
	require.NoError(t, err)
	return compiled
}

func TestDefaultAndUnconditionalDelivery(t *testing.T) {
	var absent *iripolicy.Compiled
	require.True(t, absent.Deliver(iripolicy.Facts{}))
	require.True(t, compile(t, nil, nil).Deliver(iripolicy.Facts{}))
	id, objects := policyGraph(catchAll(suppressed))
	require.True(t, compile(t, nil, objects).Deliver(iripolicy.Facts{}))
	require.False(t, compile(t, []uuid.UUID{id}, objects).Deliver(iripolicy.Facts{}))
	id, objects = policyGraph(iripolicy.Rule{
		Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{startEvent}}}, Action: suppressed,
	})
	require.True(t, compile(t, []uuid.UUID{id}, objects).Deliver(iripolicy.Facts{Events: []iripolicy.DictionaryEntry{stopEvent}}))
}

func TestRuleOrderAndGlobalFirstMatch(t *testing.T) {
	id, objects := policyGraph(
		catchAll(delivered),
		iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{startEvent}}}, Action: suppressed},
	)
	objects[0].Policy.Rules[0].Order = 20
	objects[0].Policy.Rules[1].Order = 10
	compiled := compile(t, []uuid.UUID{id}, objects)
	require.False(t, compiled.Deliver(iripolicy.Facts{Events: []iripolicy.DictionaryEntry{startEvent}}))
	require.True(t, compiled.Deliver(iripolicy.Facts{Events: []iripolicy.DictionaryEntry{stopEvent}}))
	// Compilation sorts its own copy, preserving the administrative definition.
	require.Equal(t, uint64(20), objects[0].Policy.Rules[0].Order)

	secondID, secondObjects := policyGraph(catchAll(suppressed))
	objects = append(objects, secondObjects...)
	compiled = compile(t, []uuid.UUID{id, secondID}, objects)
	require.True(t, compiled.Deliver(iripolicy.Facts{Events: []iripolicy.DictionaryEntry{stopEvent}}))
	compiled = compile(t, []uuid.UUID{secondID, id}, objects)
	require.False(t, compiled.Deliver(iripolicy.Facts{Events: []iripolicy.DictionaryEntry{stopEvent}}))
}

func TestKnownEmptyFactsDoNotMatch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		criterion iripolicy.Criterion
		facts     iripolicy.Facts
	}{
		{"event", iripolicy.Criterion{Events: []iripolicy.DictionaryEntry{startEvent}}, iripolicy.Facts{EventsKnown: true}},
		{"network function", iripolicy.Criterion{NFTypes: []iripolicy.DictionaryEntry{probeNF}}, iripolicy.Facts{NFTypesKnown: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, objects := policyGraph(iripolicy.Rule{Criteria: []iripolicy.Criterion{tc.criterion}, Action: suppressed})
			compiled := compile(t, []uuid.UUID{id}, objects)
			deliver, err := compiled.Evaluate(tc.facts)
			require.NoError(t, err)
			require.True(t, deliver, "known nonmembership must retain default delivery")
			deliver, err = compiled.Evaluate(iripolicy.Facts{})
			require.ErrorIs(t, err, iripolicy.ErrInvalidFacts)
			require.False(t, deliver)
		})
	}
}

func TestCriteriaUseANDAndEntriesUseOR(t *testing.T) {
	id, objects := policyGraph(iripolicy.Rule{Action: suppressed, Criteria: []iripolicy.Criterion{
		{NFTypes: []iripolicy.DictionaryEntry{probeNF, edgeNF}},
		{Events: []iripolicy.DictionaryEntry{startEvent, stopEvent}},
		{HandoverFormat: &rawFormat},
	}})
	compiled := compile(t, []uuid.UUID{id}, objects)
	for _, tc := range []struct {
		name    string
		facts   iripolicy.Facts
		deliver bool
	}{
		{"first OR entries", iripolicy.Facts{NFTypes: []iripolicy.DictionaryEntry{probeNF}, Events: []iripolicy.DictionaryEntry{startEvent}, HandoverFormat: &rawFormat}, false},
		{"second OR entries", iripolicy.Facts{NFTypes: []iripolicy.DictionaryEntry{edgeNF}, Events: []iripolicy.DictionaryEntry{stopEvent}, HandoverFormat: &rawFormat}, false},
		{"NF mismatch", iripolicy.Facts{NFTypes: []iripolicy.DictionaryEntry{otherNF}, Events: []iripolicy.DictionaryEntry{startEvent}, HandoverFormat: &rawFormat}, true},
		{"event mismatch", iripolicy.Facts{NFTypes: []iripolicy.DictionaryEntry{probeNF}, Events: []iripolicy.DictionaryEntry{otherEvent}, HandoverFormat: &rawFormat}, true},
		{"format mismatch", iripolicy.Facts{NFTypes: []iripolicy.DictionaryEntry{probeNF}, Events: []iripolicy.DictionaryEntry{startEvent}, HandoverFormat: &otherFormat}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := compiled.Evaluate(tc.facts)
			require.NoError(t, err)
			require.Equal(t, tc.deliver, actual)
		})
	}
}

func TestUnknownFactsFailClosedAndANDFalseDominates(t *testing.T) {
	id, objects := policyGraph(iripolicy.Rule{Action: suppressed, Criteria: []iripolicy.Criterion{
		{NFTypes: []iripolicy.DictionaryEntry{probeNF}},
		{Events: []iripolicy.DictionaryEntry{startEvent}},
		{HandoverFormat: &rawFormat},
	}})
	compiled := compile(t, []uuid.UUID{id}, objects)
	unknownEvent := iripolicy.DictionaryEntry{Owner: "DE", Name: "IRIEvents", Value: "Unknown"}
	for _, tc := range []struct {
		name  string
		facts iripolicy.Facts
	}{
		{"all missing", iripolicy.Facts{}},
		{"event missing", iripolicy.Facts{NFTypes: []iripolicy.DictionaryEntry{probeNF}, HandoverFormat: &rawFormat}},
		{"event unknown", iripolicy.Facts{NFTypes: []iripolicy.DictionaryEntry{probeNF}, Events: []iripolicy.DictionaryEntry{unknownEvent}, HandoverFormat: &rawFormat}},
		{"format missing", iripolicy.Facts{NFTypes: []iripolicy.DictionaryEntry{probeNF}, Events: []iripolicy.DictionaryEntry{startEvent}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deliver, err := compiled.Evaluate(tc.facts)
			require.ErrorIs(t, err, iripolicy.ErrInvalidFacts)
			require.False(t, deliver)
			require.False(t, compiled.Deliver(tc.facts))
		})
	}
	// A known false criterion resolves the AND even when earlier facts are absent.
	facts := iripolicy.Facts{Events: []iripolicy.DictionaryEntry{stopEvent}}
	deliver, err := compiled.Evaluate(facts)
	require.NoError(t, err)
	require.True(t, deliver)
	objects[1].Rule.Criteria[0], objects[1].Rule.Criteria[1] = objects[1].Rule.Criteria[1], objects[1].Rule.Criteria[0]
	deliver, err = compile(t, []uuid.UUID{id}, objects).Evaluate(facts)
	require.NoError(t, err)
	require.True(t, deliver)
}

func TestSnapshotOwnsDefinitionsAndGenerations(t *testing.T) {
	id, objects := policyGraph(iripolicy.Rule{Action: suppressed, Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{startEvent}}}})
	p := profile()
	compiled, err := iripolicy.Compile([]uuid.UUID{id}, objects, p, iripolicy.Limits{})
	require.NoError(t, err)
	ruleID := objects[1].ID
	objects[0].Generation = 100
	objects[0].Policy.Rules[0].ObjectID = uuid.New()
	objects[1].Rule.Action = delivered
	objects[1].Rule.Criteria[0].Events[0] = stopEvent
	p.Events[0] = otherEvent
	require.False(t, compiled.Deliver(iripolicy.Facts{Events: []iripolicy.DictionaryEntry{startEvent}}))
	expected := map[uuid.UUID]uint64{id: 3, ruleID: 5}
	require.Equal(t, expected, compiled.SourceGenerations())
	delete(compiled.SourceGenerations(), id)
	require.Equal(t, expected, compiled.SourceGenerations())

	var wg sync.WaitGroup
	failures := make(chan string, 320)
	for range 8 {
		wg.Go(func() {
			for range 20 {
				if compiled.Deliver(iripolicy.Facts{Events: []iripolicy.DictionaryEntry{startEvent}}) {
					failures <- "concurrent evaluation changed delivery"
				}
				generations := compiled.SourceGenerations()
				if len(generations) != 2 || generations[id] != 3 || generations[ruleID] != 5 {
					failures <- "concurrent source generations changed"
				}
			}
		})
	}
	wg.Wait()
	require.Empty(t, failures)
}

func TestCompilerRejectsMalformedGraphs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*uuid.UUID, *[]iripolicy.Object)
		err    error
	}{
		{"zero object ID", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[1].ID = uuid.Nil }, iripolicy.ErrInvalidObject},
		{"duplicate object ID", func(_ *uuid.UUID, objects *[]iripolicy.Object) { *objects = append(*objects, (*objects)[1]) }, iripolicy.ErrDuplicateObjectID},
		{"both object kinds", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[1].Policy = &iripolicy.Policy{} }, iripolicy.ErrInvalidObject},
		{"neither object kind", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[1].Rule = nil }, iripolicy.ErrInvalidObject},
		{"missing policy", func(id *uuid.UUID, _ *[]iripolicy.Object) { *id = uuid.New() }, iripolicy.ErrMissingObject},
		{"rule used as policy", func(id *uuid.UUID, objects *[]iripolicy.Object) { *id = (*objects)[1].ID }, iripolicy.ErrWrongObjectKind},
		{"empty policy", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[0].Policy.Rules = nil }, iripolicy.ErrInvalidObject},
		{"missing rule", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[0].Policy.Rules[0].ObjectID = uuid.New() }, iripolicy.ErrMissingObject},
		{"policy used as rule", func(id *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[0].Policy.Rules[0].ObjectID = *id }, iripolicy.ErrWrongObjectKind},
		{"zero rule ID", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[0].Policy.Rules[0].ObjectID = uuid.Nil }, iripolicy.ErrInvalidObject},
		{"zero order", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[0].Policy.Rules[0].Order = 0 }, iripolicy.ErrInvalidOrder},
		{"duplicate order", func(_ *uuid.UUID, objects *[]iripolicy.Object) {
			p := (*objects)[0].Policy
			p.Rules = append(p.Rules, p.Rules[0])
		}, iripolicy.ErrInvalidOrder},
		{"missing action", func(_ *uuid.UUID, objects *[]iripolicy.Object) {
			(*objects)[1].Rule.Action = iripolicy.DictionaryEntry{}
		}, iripolicy.ErrInvalidAction},
		{"unrecognized action", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[1].Rule.Action.Value = "Unknown" }, iripolicy.ErrInvalidAction},
		{"national action unsupported", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[1].Rule.Action.Owner = "DE" }, iripolicy.ErrInvalidAction},
		{"empty criteria", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[1].Rule.Criteria = nil }, iripolicy.ErrInvalidObject},
		{"empty criterion", func(_ *uuid.UUID, objects *[]iripolicy.Object) {
			(*objects)[1].Rule.Criteria = []iripolicy.Criterion{{}}
		}, iripolicy.ErrInvalidObject},
		{"empty NF choice", func(_ *uuid.UUID, objects *[]iripolicy.Object) {
			(*objects)[1].Rule.Criteria = []iripolicy.Criterion{{NFTypes: []iripolicy.DictionaryEntry{}}}
		}, iripolicy.ErrInvalidObject},
		{"empty event choice", func(_ *uuid.UUID, objects *[]iripolicy.Object) {
			(*objects)[1].Rule.Criteria = []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{}}}
		}, iripolicy.ErrInvalidObject},
		{"ambiguous empty choice", func(_ *uuid.UUID, objects *[]iripolicy.Object) {
			(*objects)[1].Rule.Criteria = []iripolicy.Criterion{{NFTypes: []iripolicy.DictionaryEntry{}, Events: []iripolicy.DictionaryEntry{allEvents}}}
		}, iripolicy.ErrInvalidObject},
		{"ambiguous criterion", func(_ *uuid.UUID, objects *[]iripolicy.Object) {
			(*objects)[1].Rule.Criteria = []iripolicy.Criterion{{NFTypes: []iripolicy.DictionaryEntry{probeNF}, Events: []iripolicy.DictionaryEntry{startEvent}}}
		}, iripolicy.ErrInvalidObject},
		{"unsupported criterion", func(_ *uuid.UUID, objects *[]iripolicy.Object) {
			(*objects)[1].Rule.Criteria = []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{{Owner: "ETSI", Name: "IRIEvents", Value: "Invented"}}}}
		}, iripolicy.ErrUnsupportedEntry},
		{"invalid policy name", func(_ *uuid.UUID, objects *[]iripolicy.Object) { (*objects)[0].Policy.Name = strings.Repeat("a", 256) }, iripolicy.ErrInvalidObject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, objects := policyGraph(catchAll(suppressed))
			tc.mutate(&id, &objects)
			_, err := iripolicy.Compile([]uuid.UUID{id}, objects, profile(), iripolicy.Limits{})
			require.ErrorIs(t, err, tc.err)
		})
	}
	id, objects := policyGraph(catchAll(delivered))
	_, err := iripolicy.Compile([]uuid.UUID{id, id}, objects, profile(), iripolicy.Limits{})
	require.ErrorIs(t, err, iripolicy.ErrDuplicateReference)
	// Unreferenced invalid objects still invalidate the complete graph.
	objects[0].Policy.Rules[0].ObjectID = uuid.New()
	require.ErrorIs(t, iripolicy.ValidateObjects(objects, profile(), iripolicy.Limits{}), iripolicy.ErrMissingObject)
	_, err = iripolicy.Compile(nil, objects, profile(), iripolicy.Limits{})
	require.ErrorIs(t, err, iripolicy.ErrMissingObject)
}

func TestErrorMessagesExcludeDefinitionContent(t *testing.T) {
	secret := "private-policy-value"
	id, objects := policyGraph(iripolicy.Rule{Action: iripolicy.DictionaryEntry{Owner: secret, Name: secret, Value: secret}})
	objects[0].Policy.Name = secret
	_, err := iripolicy.Compile([]uuid.UUID{id}, objects, profile(), iripolicy.Limits{})
	require.Error(t, err)
	require.NotContains(t, err.Error(), secret)
	require.True(t, errors.Is(err, iripolicy.ErrInvalidAction))
}

func TestWildcardIsNotARuntimeEventFact(t *testing.T) {
	id, objects := policyGraph(iripolicy.Rule{Action: suppressed, Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{startEvent}}}})
	p := profile()
	p.Events = append(p.Events, allEvents)
	compiled, err := iripolicy.Compile([]uuid.UUID{id}, objects, p, iripolicy.Limits{})
	require.NoError(t, err)
	deliver, err := compiled.Evaluate(iripolicy.Facts{Events: []iripolicy.DictionaryEntry{allEvents}})
	require.ErrorIs(t, err, iripolicy.ErrInvalidFacts)
	require.False(t, deliver)
}
