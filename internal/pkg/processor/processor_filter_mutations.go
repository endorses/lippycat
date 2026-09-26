//go:build processor || tap || all

package processor

import (
	"errors"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrFilterReconciliation means desired policy is durable, but its effective
// local installation failed. Only authenticated startup reconciliation clears it.
var ErrFilterReconciliation = errors.New("filter policy committed but local reconciliation failed; processing blocked until restart")

func (p *Processor) defaultHunterFilterTarget() bool {
	target, ok := p.filterTarget.(*filtering.HunterTarget)
	return ok && target.Manager() == p.filterManager
}

func (p *Processor) filterMutationReady() error {
	if p.filterReconcileFault != nil {
		return p.filterReconcileFault
	}
	if p.filterManager.Fault() != nil {
		return filtering.ErrFilterStoreFault
	}
	return nil
}

func (p *Processor) filterProcessingBlocked() bool {
	return p.filterPolicyBlocked.Load() || (p.filterManager != nil && p.filterManager.Fault() != nil)
}

func (p *Processor) blockFilterProcessing() {
	p.filterPolicyBlocked.Store(true)
	// Cancellation closes capture and delivery through the processor's existing
	// owner shutdown path; the ingress gate also covers callers outside Start.
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *Processor) updateManagedFilter(filter *management.Filter) (uint32, error) {
	p.filterMutationMu.Lock()
	defer p.filterMutationMu.Unlock()
	if err := p.filterMutationReady(); err != nil {
		return 0, err
	}
	var validate func(*management.Filter) error
	if target, ok := p.filterTarget.(interface {
		ValidateFilter(*management.Filter) error
	}); ok {
		validate = target.ValidateFilter
	}
	accepted, count, err := p.filterManager.UpdateValidated(filter, validate)
	if accepted == nil {
		if p.filterManager.Fault() != nil {
			p.blockFilterProcessing()
		}
		return count, err
	}
	// The accepted value is the committed normalized clone, including generated ID.
	// Committed cleanup/distribution errors do not undo local desired policy.
	if p.filterTarget != nil && !p.defaultHunterFilterTarget() {
		_, targetErr := p.filterTarget.ApplyFilter(accepted)
		if targetErr != nil {
			p.filterReconcileFault = ErrFilterReconciliation
			p.blockFilterProcessing()
			return count, &securestore.CommitError{Outcome: securestore.Committed, Op: "apply committed filter policy", Err: errors.Join(err, ErrFilterReconciliation)}
		}
	}
	return count, err
}

func (p *Processor) deleteManagedFilter(id string) (uint32, error) {
	p.filterMutationMu.Lock()
	defer p.filterMutationMu.Unlock()
	if err := p.filterMutationReady(); err != nil {
		return 0, err
	}
	if id == "" {
		return 0, filtering.ErrFilterInvalid
	}
	count, err := p.filterManager.Delete(id)
	if securestore.OutcomeOf(err) != securestore.Committed {
		if p.filterManager.Fault() != nil {
			p.blockFilterProcessing()
		}
		return count, err
	}
	if p.filterTarget != nil && !p.defaultHunterFilterTarget() {
		_, targetErr := p.filterTarget.RemoveFilter(id)
		if targetErr != nil {
			p.filterReconcileFault = ErrFilterReconciliation
			p.blockFilterProcessing()
			return count, &securestore.CommitError{Outcome: securestore.Committed, Op: "apply committed filter deletion", Err: errors.Join(err, ErrFilterReconciliation)}
		}
	}
	return count, err
}

// Never include nested persistence/capture errors: they can contain selectors,
// filter IDs or expanded BPF. Outcome and class provide actionable diagnostics.
func filterMutationStatus(err error) error {
	switch {
	case errors.Is(err, ErrFilterReconciliation):
		return status.Error(codes.FailedPrecondition, ErrFilterReconciliation.Error())
	case errors.Is(err, filtering.ErrFilterStoreFault) || securestore.OutcomeOf(err) == securestore.Uncertain:
		return status.Error(codes.Aborted, "filter storage commitment uncertain; restart and reconcile before retrying")
	case securestore.OutcomeOf(err) == securestore.Committed:
		if errors.Is(err, filtering.ErrFilterDistribution) {
			return status.Error(codes.Unavailable, "filter policy committed; hunter distribution incomplete")
		}
		return status.Error(codes.Internal, "filter policy committed; storage cleanup failed")
	case errors.Is(err, filtering.ErrFilterNotFound):
		return status.Error(codes.NotFound, "filter not found")
	case errors.Is(err, filtering.ErrFilterInvalid):
		return status.Error(codes.InvalidArgument, "invalid managed filter")
	case errors.Is(err, filtering.ErrLocalFilterCapability):
		return status.Error(codes.FailedPrecondition, "local filter capability is unavailable")
	case errors.Is(err, filtering.ErrFilterManagerClosed):
		return status.Error(codes.Unavailable, "filter manager is closed")
	default:
		return status.Error(codes.Internal, "filter storage operation failed before commitment")
	}
}
