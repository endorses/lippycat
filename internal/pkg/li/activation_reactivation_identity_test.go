//go:build li

package li

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestEquivalentReactivationIdentity(t *testing.T) {
	xid := uuid.New()
	base := &InterceptTask{
		XID: xid,
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:alice@example"},
			{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
		},
		DeliveryType: DeliveryX2andX3,
	}

	tests := []struct {
		name string
		edit func(*InterceptTask)
		want bool
	}{
		{name: "same identity", want: true},
		{name: "target order and duplicates ignored", edit: func(task *InterceptTask) {
			task.Targets = []TargetIdentity{base.Targets[1], base.Targets[0], base.Targets[1]}
		}, want: true},
		{name: "destinations replaceable", edit: func(task *InterceptTask) { task.DestinationIDs = []uuid.UUID{uuid.New()} }, want: true},
		{name: "mediation and lifecycle replaceable", edit: func(task *InterceptTask) { task.ImplicitDeactivationAllowed = true }, want: true},
		{name: "XID differs", edit: func(task *InterceptTask) { task.XID = uuid.New() }, want: false},
		{name: "delivery differs", edit: func(task *InterceptTask) { task.DeliveryType = DeliveryX2Only }, want: false},
		{name: "target type differs", edit: func(task *InterceptTask) { task.Targets[0].Type = TargetTypeNAI }, want: false},
		{name: "target value differs", edit: func(task *InterceptTask) { task.Targets[0].Value = "sip:bob@example" }, want: false},
		{name: "target added", edit: func(task *InterceptTask) {
			task.Targets = append(task.Targets, TargetIdentity{Type: TargetTypeNAI, Value: "alice@example"})
		}, want: false},
		{name: "target removed", edit: func(task *InterceptTask) { task.Targets = task.Targets[:1] }, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := cloneActivationTask(base)
			if tt.edit != nil {
				tt.edit(candidate)
			}
			assert.Equal(t, tt.want, equivalentReactivationIdentity(base, candidate))
		})
	}
}

func TestCanonicalizeTargetsDoesNotAliasInput(t *testing.T) {
	targets := []TargetIdentity{{Type: TargetTypeTELURI, Value: "b"}, {Type: TargetTypeSIPURI, Value: "a"}}
	canonical := canonicalizeTargets(targets)
	canonical[0].Value = "changed"
	assert.Equal(t, "b", targets[0].Value)
}
