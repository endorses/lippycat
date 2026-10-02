//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/stretchr/testify/require"
)

func processorConflictAcknowledgment(t *testing.T, body []byte) []byte {
	t.Helper()
	var request struct {
		Message struct {
			Type string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
			schema.X1RequestMessage
		} `xml:"x1RequestMessage"`
	}
	require.NoError(t, xml.Unmarshal(body, &request))
	response := struct {
		XMLName xml.Name `xml:"http://uri.etsi.org/03221/X1/2017/10 X1Response"`
		XSI     string   `xml:"xmlns:xsi,attr"`
		Message struct {
			Type string `xml:"xsi:type,attr"`
			schema.X1RequestMessage
			OK string `xml:"oK"`
		} `xml:"x1ResponseMessage"`
	}{XSI: "http://www.w3.org/2001/XMLSchema-instance"}
	response.Message.Type = strings.TrimSuffix(request.Message.Type, "Request") + "Response"
	response.Message.X1RequestMessage = request.Message.X1RequestMessage
	response.Message.OK = "AcknowledgedAndCompleted"
	encoded, err := xml.Marshal(response)
	require.NoError(t, err)
	return encoded
}

func TestProcessorConflictRevokesQueuedX2AndX3(t *testing.T) {
	for _, journal := range []bool{false, true} {
		name := "memory"
		if journal {
			name = "journal"
		}
		t.Run(name, func(t *testing.T) {
			f := newPersistentProcessorFixture(t)
			f.taskDeliveryType, f.destinationDeliveryType = "X2andX3", "X2andX3"
			f.endTime = time.Now().Add(time.Hour).UTC()
			f.config.LIADMFReconcileInterval = 20 * time.Millisecond
			if !journal {
				f.config.LIDeliveryX2SpoolDir, f.config.LIDeliveryX2SpoolKeyFile, f.config.LIDeliveryX2SpoolKeyID = "", "", ""
				f.config.LIDeliveryX2SpoolReadKeys = nil
				f.config.LIDeliveryX2SpoolMaxBytes = 0
				f.config.LIDeliveryX3SpoolDir, f.config.LIDeliveryX3SpoolKeyFile, f.config.LIDeliveryX3SpoolKeyID = "", "", ""
				f.config.LIDeliveryX3SpoolMaxBytes = 0
				f.config.LIDeliveryX3SpoolReplayPolicy = ""
			}
			p := f.open(t)
			require.NoError(t, p.startLIManager())
			// An authenticated administrative modification establishes push
			// ownership without changing the initially matching snapshot scope.
			require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &f.endTime}))
			before, err := p.liManager.GetTaskDetails(f.xid)
			require.NoError(t, err)
			filterID := "li-" + f.xid.String() + "-0"
			sip := dirSIPPacket("INVITE sip:remote@example.invalid SIP/2.0", 0, f.target, "sip:remote@example.invalid", "", "")
			sip.Timestamp = time.Now().UTC()
			p.processLIPacketWithProvenance(sip, []string{filterID}, nil)
			captureAuthorizationPacket(t, p, f, dirCallID, 1)
			if journal {
				finalized := p.callLifecycle.Finalize(dirCallID, CallFinalizationProtocolComplete)
				require.NoError(t, finalized.Err)
			}
			// Memory-only call finalization intentionally discards queued media.
			// Keep that call active so conflict narrowing is the revocation owner.
			require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
			require.Eventually(t, func() bool {
				if journal {
					return liDeliveryClient.JournalStats().Persisted > 0 && liDeliveryClient.X3JournalStats().Persisted > 0
				}
				stats := liDeliveryClient.DestinationStats()[f.did]
				return stats.X2QueueDepth > 0 && stats.X3QueueDepth > 0
			}, 5*time.Second, time.Millisecond, "both products must be retained while MDF is unavailable")
			f.mu.Lock()
			f.taskDeliveryType = "X2Only"
			f.mu.Unlock()
			require.Eventually(t, func() bool {
				current, err := p.liManager.GetTaskDetails(f.xid)
				return err == nil && current.Definition.Conflict && current.DeliveryType == li.DeliveryX2Only && current.ActivationGeneration > before.ActivationGeneration
			}, 5*time.Second, time.Millisecond)
			require.Eventually(t, func() bool {
				return liDeliveryClient.QueueDepth() == 0 && (!journal || (liDeliveryClient.JournalStats().Persisted == 0 && liDeliveryClient.X3JournalStats().Persisted == 0))
			}, 5*time.Second, time.Millisecond, "old-generation X2 and X3 must be revoked at conflict narrowing")
			admission, ok := p.liManager.AcquireTaskAdmission(f.xid, before.ActivationGeneration)
			if admission != nil {
				admission.Release()
			}
			require.False(t, ok)
			require.False(t, p.liManager.ReplayTaskAuthorized(f.xid, before.ActivationGeneration))
			require.NoError(t, p.Shutdown())
			if journal {
				restarted := f.open(t)
				require.NoError(t, restarted.startLIManager())
				require.Zero(t, liDeliveryClient.JournalStats().Persisted)
				require.Zero(t, liDeliveryClient.X3JournalStats().Persisted)
				held, err := restarted.liManager.GetTaskDetails(f.xid)
				require.NoError(t, err)
				require.True(t, held.Definition.Conflict)
				require.False(t, restarted.liManager.ReplayTaskAuthorized(f.xid, held.ActivationGeneration))
			}
		})
	}
}

func TestProcessorWiderSnapshotConflictPreservesLiveDelivery(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	f.taskDeliveryType, f.destinationDeliveryType = "X2andX3", "X2andX3"
	f.endTime = time.Now().Add(time.Hour).UTC()
	f.config.LIADMFReconcileInterval = 20 * time.Millisecond
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &f.endTime}))
	before, err := p.liManager.GetTaskDetails(f.xid)
	require.NoError(t, err)
	f.mu.Lock()
	f.endTime = f.endTime.Add(time.Hour)
	f.mu.Unlock()
	require.Eventually(t, func() bool {
		current, err := p.liManager.GetTaskDetails(f.xid)
		return err == nil && current.Definition.Conflict
	}, 5*time.Second, time.Millisecond)
	current, err := p.liManager.GetTaskDetails(f.xid)
	require.NoError(t, err)
	require.Equal(t, before.ActivationGeneration, current.ActivationGeneration)
	require.Equal(t, before.EndTime, current.EndTime)
	// New products still belong to the unchanged common authorization. The
	// conflict with a wider snapshot must not poison that generation's gate.
	sip := dirSIPPacket("INVITE sip:remote@example.invalid SIP/2.0", 0, f.target, "sip:remote@example.invalid", "", "")
	sip.Timestamp = time.Now().UTC()
	p.processLIPacketWithProvenance(sip, []string{"li-" + f.xid.String() + "-0"}, nil)
	captureAuthorizationPacket(t, p, f, dirCallID, 1)
	require.NoError(t, p.callLifecycle.Finalize(dirCallID, CallFinalizationProtocolComplete).Err)
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Eventually(t, func() bool {
		return liDeliveryClient.JournalStats().Persisted > 0 && liDeliveryClient.X3JournalStats().Persisted > 0
	}, 5*time.Second, time.Millisecond)
	require.False(t, p.liManager.ReplayTaskAuthorized(f.xid, current.ActivationGeneration))
}
