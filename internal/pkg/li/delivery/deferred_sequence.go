//go:build li

package delivery

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
)

// PrepareDeferredX3 reserves the same exact product, queue bytes, journal bytes
// and call/drain eligibility as PrepareX3. Only its fixed-width sequence field
// may be completed later; ordinary SendAcceptedX3 cannot emit the template.
func (c *Client) PrepareDeferredX3(xid, did uuid.UUID, data []byte, m DeliveryMetadata, context x2x3.SequenceContext) (*AcceptedX3, error) {
	checkpoint, err := journalPDUCheckpoint(data, PDUTypeX3, xid, true)
	if err != nil {
		return nil, err
	}
	if checkpoint.Context != context || checkpoint.Next != 1 {
		return nil, fmt.Errorf("invalid deferred X3 template")
	}
	// Ordinary delivery re-admits its current call before emission and retains
	// no durable closure identity. Preserve that existing lifetime contract.
	accepted, err := c.prepareX3(xid, did, data, m, c.x3Journal != nil)
	if err != nil {
		return nil, err
	}
	accepted.deferredSequence = true
	accepted.sequenceContext = context
	return accepted, nil
}

// SendAcceptedX3WithSequence consumes a deferred permit exactly once and changes
// only its sequence field. The existing monotonic revocation/expiry gates and
// journal checkpointing run on the resulting final immutable product.
func (c *Client) SendAcceptedX3WithSequence(accepted *AcceptedX3, sequence uint32) error {
	if accepted == nil || accepted.client != c || !accepted.deferredSequence || !accepted.used.CompareAndSwap(false, true) {
		return fmt.Errorf("invalid or consumed deferred X3 admission")
	}
	if err := x2x3.StampProductSequence(accepted.item.data, accepted.sequenceContext, sequence); err != nil {
		accepted.queue.mu.Lock()
		accepted.queue.reserved[1]--
		accepted.queue.reservedBytes[1] -= int64(len(accepted.item.data))
		accepted.queue.mu.Unlock()
		accepted.reservation.Release()
		if accepted.trackCall {
			accepted.client.releasePreparedCall(accepted.item, false)
		}
		accepted.item.payload.release()
		return err
	}
	return c.sendAcceptedX3Claimed(accepted)
}

// DeferredX3Eligible is a conservative pre-sequence check. Send still rechecks
// the same monotonic gates atomically with delivery admission.
func (c *Client) DeferredX3Eligible(accepted *AcceptedX3) bool {
	return accepted != nil && accepted.client == c && accepted.deferredSequence && !accepted.used.Load() && !c.stopped.Load() && c.itemEligible(accepted.queue.did, accepted.item, false)
}
