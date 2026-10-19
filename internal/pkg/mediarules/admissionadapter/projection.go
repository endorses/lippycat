// Package admissionadapter retains the media observer compatibility interface
// over the shared learned-binding candidate admission projection.
package admissionadapter

import (
	"context"

	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	generic "github.com/endorses/lippycat/internal/pkg/learnedrules/admissionadapter"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
)

type Projection struct{ *generic.Projection }

func New(ctx context.Context, controller *mediaadmission.Controller, domains []mediaadmission.DomainID, onError func(error)) (*Projection, error) {
	p, err := generic.New(ctx, controller, domains, onError)
	if err != nil {
		return nil, err
	}
	return &Projection{Projection: p}, nil
}

// NewForSource retains complete bindings while installing only the exact local
// source/domain scopes through the shared projection.
func NewForSource(ctx context.Context, controller *mediaadmission.Controller, hunterID string, domains []mediaadmission.DomainID, onError func(error)) (*Projection, error) {
	p, err := generic.NewForSource(ctx, controller, hunterID, domains, onError)
	if err != nil {
		return nil, err
	}
	return &Projection{Projection: p}, nil
}

func (p *Projection) OnMediaRulesChanged(change mediarules.Change) {
	next := learnedrules.Change{Snapshot: learnedrules.Snapshot{
		Session:  learnedrules.Session{ProcessorID: change.Session.ProcessorID, Generation: change.Session.Generation},
		Revision: learnedrules.Revision(change.Revision), Sequence: change.Sequence, Ready: change.Ready,
	}, ResyncRequired: change.ResyncRequired}
	for _, rule := range change.Active {
		next.Active = append(next.Active, mediarules.ToBinding(rule))
	}
	p.OnLearnedRulesChanged(next)
}
