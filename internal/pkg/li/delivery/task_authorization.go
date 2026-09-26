//go:build li

package delivery

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
)

// Coalesce notifications without queue locks, I/O, or administrative worker waits.
func (c *Client) taskAuthorizationChanged() {
	c.taskRevision.Add(1)
	select {
	case c.taskNotify <- struct{}{}:
	default:
	}
}

func (c *Client) taskAuthorizationDispatcher() {
	defer c.wg.Done()
	for {
		select {
		case <-c.taskStop:
			return
		case <-c.taskNotify:
			c.queuesMu.RLock()
			for _, q := range c.queues {
				q.signal()
			}
			c.queuesMu.RUnlock()
		}
	}
}

// PublishX3TaskAuthorization is the ordered committed control-plane boundary.
// Only this method can introduce an identity in authoritative mode. Replay and
// packet metadata cannot recreate a retired identity. Missing facts deny even
// previously prepared work, so terminal/replaced generations need no tombstone.
// The manager must serialize these publications with task lifecycle changes.
func (c *Client) PublishX3TaskAuthorization(task *li.InterceptTask) {
	if task == nil {
		return
	}
	if !c.config.AuthoritativeTaskAuthorization {
		if task.Status == li.TaskStatusActive {
			c.SetX3TaskAuthorization(task.XID, task.ActivationGeneration, li.TaskAuthorizationCutoff(task))
		} else {
			c.CancelTask(task.XID, task.ActivationGeneration)
		}
		return
	}
	c.gateMu.Lock()
	defer c.gateMu.Unlock()
	previous, known := c.currentTasks[task.XID]
	if known && (previous != task.ActivationGeneration || task.Status != li.TaskStatusActive) {
		key := x3TaskIdentity{task.XID, previous}
		delete(c.taskFacts, key)
		delete(c.revokedTasks, key)
		delete(c.expiredTaskControls, key)
		delete(c.currentTasks, task.XID)
	}
	if task.Status == li.TaskStatusActive {
		key := x3TaskIdentity{task.XID, task.ActivationGeneration}
		if _, exists := c.taskFacts[key]; !exists && len(c.taskFacts) >= maxDeliveryGateIdentities {
			c.gateFault = true
			return
		}
		end := li.TaskAuthorizationCutoff(task)
		now := time.Now()
		old := c.taskFacts[key]
		if !end.IsZero() && !now.Before(end) || !old.IsZero() && !now.Before(old) {
			c.revokedTasks[key] = true
		}
		c.currentTasks[task.XID] = task.ActivationGeneration
		c.taskFacts[key] = end
	}
	c.taskAuthorizationChanged()
}
