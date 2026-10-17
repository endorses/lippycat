//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/packetdedup"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// beginLITaskDedup runs only after current task/call authorization. The source
// observation is supplied by the trusted ingress composition, never derived
// from a packet's claimed NodeID. Independent tasks own separate consumer keys.
func (p *Processor) beginLITaskDedup(task *li.InterceptTask, pkt *types.PacketDisplay) (*packetdedup.Claim, bool) {
	if p.packetDuplicates == nil || p.liStorage == nil || pkt == nil || pkt.VoIPData == nil {
		return nil, false
	}
	value, ok := p.liStorage.packetDedup.Load(pkt)
	if !ok {
		return nil, false
	}
	observation := value.(packetdedup.Observation)
	product := "x2"
	if pkt.VoIPData.IsRTP {
		product = "x3"
	}
	if (product == "x2" && task.DeliveryType == li.DeliveryX3Only) || (product == "x3" && task.DeliveryType == li.DeliveryX2Only) {
		return nil, false
	}
	observation.Consumer = fmt.Sprintf("li/%s/%d/%s", task.XID, task.ActivationGeneration, product)
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		admission, active := p.liManager.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
		if !active {
			return nil, true
		}
		if pkt.VoIPData.IsRTP && pkt.VoIPData.CallID != "" && p.callLifecycle != nil {
			probe, err := p.callLifecycle.Admit(pkt.VoIPData.CallID)
			if err != nil {
				admission.Release()
				return nil, true
			}
			probe.Release()
		}
		decision, claim := p.packetDuplicates.Begin(observation)
		admission.Release()
		switch decision {
		case packetdedup.Duplicate:
			return nil, true
		case packetdedup.InFlight:
			// A pending owner is not proof of acceptance. Wait within the
			// configured evidence horizon, then retry against current gates.
			timer := time.NewTimer(p.config.PacketDedup.Window)
			select {
			case <-claim.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, true
			}
		case packetdedup.Accept:
			return claim, false
		default:
			return nil, false // Every conservative Retain decision stays eligible.
		}
	}
}
