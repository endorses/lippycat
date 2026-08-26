//go:build li

package li

import (
	"slices"
	"sort"
)

// canonicalTaskDefinition contains only enforcement-affecting activation
// fields. Runtime lifecycle fields must never participate in retry identity.
type canonicalTaskDefinition struct {
	XID                         [16]byte
	Targets                     []TargetIdentity
	DestinationIDs              [][16]byte
	DeliveryType                DeliveryType
	StartTimeUnixNano           int64
	StartTimeSet                bool
	EndTimeUnixNano             int64
	EndTimeSet                  bool
	ImplicitDeactivationAllowed bool
}

// canonicalizeTargets returns a sorted, duplicate-free copy of targets. The
// returned slice never aliases the caller's task definition.
func canonicalizeTargets(targets []TargetIdentity) []TargetIdentity {
	canonical := append([]TargetIdentity(nil), targets...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Type != canonical[j].Type {
			return canonical[i].Type < canonical[j].Type
		}
		return canonical[i].Value < canonical[j].Value
	})
	return slices.Compact(canonical)
}

func canonicalizeTaskDefinition(task *InterceptTask) canonicalTaskDefinition {
	c := canonicalTaskDefinition{
		XID:                         task.XID,
		DeliveryType:                task.DeliveryType,
		ImplicitDeactivationAllowed: task.ImplicitDeactivationAllowed,
	}
	if !task.StartTime.IsZero() {
		c.StartTimeSet = true
		c.StartTimeUnixNano = task.StartTime.UnixNano()
	}
	if !task.EndTime.IsZero() {
		c.EndTimeSet = true
		c.EndTimeUnixNano = task.EndTime.UnixNano()
	}

	c.Targets = canonicalizeTargets(task.Targets)

	c.DestinationIDs = make([][16]byte, len(task.DestinationIDs))
	for i, did := range task.DestinationIDs {
		c.DestinationIDs[i] = did
	}
	slices.SortFunc(c.DestinationIDs, func(a, b [16]byte) int { return slices.Compare(a[:], b[:]) })
	c.DestinationIDs = slices.Compact(c.DestinationIDs)
	return c
}

// equivalentReactivationIdentity compares the fields that identify a retained
// interception across explicit activations. Destinations, mediation times, and
// lifecycle options are deliberately replaceable and therefore excluded.
func equivalentReactivationIdentity(a, b *InterceptTask) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.XID == b.XID &&
		a.DeliveryType == b.DeliveryType &&
		slices.Equal(canonicalizeTargets(a.Targets), canonicalizeTargets(b.Targets))
}

func equivalentTaskDefinition(a, b *InterceptTask) bool {
	ca, cb := canonicalizeTaskDefinition(a), canonicalizeTaskDefinition(b)
	return ca.XID == cb.XID &&
		ca.DeliveryType == cb.DeliveryType &&
		ca.StartTimeSet == cb.StartTimeSet && ca.StartTimeUnixNano == cb.StartTimeUnixNano &&
		ca.EndTimeSet == cb.EndTimeSet && ca.EndTimeUnixNano == cb.EndTimeUnixNano &&
		ca.ImplicitDeactivationAllowed == cb.ImplicitDeactivationAllowed &&
		slices.Equal(ca.Targets, cb.Targets) && slices.Equal(ca.DestinationIDs, cb.DestinationIDs)
}
