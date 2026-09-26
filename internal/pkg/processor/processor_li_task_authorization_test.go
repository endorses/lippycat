//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/stretchr/testify/require"
)

// Processor tests require a role tag as well as li (for example -tags all,li).
// Exercise actual committed administrative mutations, rather than simulating an
// extension by replacing packet metadata.
func TestProcessorX3CommittedTimingPolicy(t *testing.T) {
	for _, journal := range []bool{false, true} {
		name := "memory"
		if journal {
			name = "journal"
		}
		t.Run(name, func(t *testing.T) {
			for _, change := range []string{"extend", "disable_implicit", "remove_end"} {
				t.Run(change, func(t *testing.T) {
					f := newPersistentProcessorFixture(t)
					if !journal {
						f.config.LIDeliveryX3SpoolDir = ""
						f.config.LIDeliveryX3SpoolKeyFile = ""
						f.config.LIDeliveryX3SpoolKeyID = ""
						f.config.LIDeliveryX3SpoolMaxBytes = 0
						f.config.LIDeliveryX3SpoolReplayPolicy = ""
					}
					p := f.open(t)
					require.NoError(t, p.startLIManager())
					original, err := p.liManager.GetTaskDetails(f.xid)
					require.NoError(t, err)
					oldEnd := time.Now().Add(time.Second).UTC()
					require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &oldEnd}))
					captureAuthorizationPacket(t, p, f, "before-cutoff", 1)
					modification := &li.TaskModification{}
					switch change {
					case "extend":
						end := oldEnd.Add(time.Minute)
						modification.EndTime = &end
					case "disable_implicit":
						implicit := false
						modification.ImplicitDeactivationAllowed = &implicit
					case "remove_end":
						modification.EndTime = &time.Time{}
					}
					require.NoError(t, p.liManager.ModifyTask(f.xid, modification))
					require.True(t, time.Now().Before(oldEnd), "the committed modification must precede the original deadline")
					current, err := p.liManager.GetTaskDetails(f.xid)
					require.NoError(t, err)
					require.Equal(t, original.ActivationGeneration, current.ActivationGeneration)
					// A timer tied to the exact cutoff establishes ordering; worker
					// completion is observed through actual MDF products below.
					timer := time.NewTimer(time.Until(oldEnd))
					defer timer.Stop()
					<-timer.C
					products := f.listenMDF(t)
					captureAuthorizationPacket(t, p, f, "after-cutoff", 2)
					for range 2 {
						select {
						case product := <-products:
							require.Equal(t, f.xid, product.Header.XID)
						case <-time.After(5 * time.Second):
							t.Fatal("committed policy must preserve retained and new X3 beyond the original cutoff")
						}
					}
					require.NoError(t, p.Shutdown())
				})
			}
		})
	}
}

func captureAuthorizationPacket(t *testing.T, p *Processor, f *persistentProcessorFixture, callID string, sequence uint16) {
	t.Helper()
	packet := dirRTPPacket(42, dirUEAddr, dirUEPort, dirCoreAddr, dirCorePort)
	packet.Timestamp = time.Now().UTC()
	packet.VoIPData.CallID, packet.VoIPData.SequenceNum = callID, sequence
	p.processLIPacketWithProvenance(packet, nil, []string{"li-" + f.xid.String() + "-0"})
}

func TestProcessorX3ExplicitDeactivationReplayPolicy(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	end := time.Now().Add(time.Second).UTC()
	implicit := false
	require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &end, ImplicitDeactivationAllowed: &implicit}))
	require.True(t, time.Now().Before(end))
	timer := time.NewTimer(time.Until(end))
	defer timer.Stop()
	<-timer.C
	task, err := p.liManager.GetTaskDetails(f.xid)
	require.NoError(t, err)
	require.True(t, task.IsActive(), "explicit deactivation policy keeps the task active beyond EndTime")
	destination, err := liDeliveryMgr.GetDestination(f.did)
	require.NoError(t, err)
	record := delivery.JournalRecord{StateIncarnation: p.liManager.StateIncarnation(), XID: f.xid, DID: f.did,
		TaskGeneration: task.ActivationGeneration, DestinationGeneration: li.DestinationDeliveryGeneration(destination)}
	require.False(t, p.authorizePersistentX3Replay(record), "a modified definition still requires startup confirmation before replay")
	products := f.listenMDF(t)
	captureAuthorizationPacket(t, p, f, "explicit-after-end", 1)
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	select {
	case <-products:
	case <-time.After(5 * time.Second):
		t.Fatal("persistent X3 admission must respect explicit deactivation policy")
	}
	require.NoError(t, p.Shutdown())
}

func TestProcessorX3ExplicitDeactivationHeldReplay(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	p := f.open(t)
	f.captureAndClose(t, p)
	end := time.Now().Add(2 * time.Second).UTC()
	implicit := false
	require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &end, ImplicitDeactivationAllowed: &implicit}))
	f.mu.Lock()
	f.endTime, f.explicitDeactivation = end, true
	f.mu.Unlock()
	require.NoError(t, p.Shutdown())
	restarted := f.open(t)
	path, manifest := exportProcessorX3Approval(t)
	require.Len(t, manifest.Records, 2)
	require.NoError(t, restarted.startLIManager())
	require.True(t, time.Now().Before(end))
	timer := time.NewTimer(time.Until(end))
	defer timer.Stop()
	<-timer.C
	products := f.listenMDF(t)
	require.NoError(t, liDeliveryClient.ReplayX3JournalManifest(path, restarted.authorizePersistentX3Replay))
	for range 2 {
		select {
		case product := <-products:
			require.Equal(t, f.xid, product.Header.XID)
		case <-time.After(5 * time.Second):
			t.Fatal("held product must replay when committed policy requires explicit deactivation")
		}
	}
	require.NoError(t, restarted.Shutdown())
}

func TestProcessorX3CommittedCutoffSuppressesRetainedWork(t *testing.T) {
	for _, journal := range []bool{false, true} {
		name := "memory"
		if journal {
			name = "journal"
		}
		t.Run(name, func(t *testing.T) {
			for _, change := range []string{"shorten", "enable_implicit"} {
				t.Run(change, func(t *testing.T) {
					f := newPersistentProcessorFixture(t)
					if !journal {
						f.config.LIDeliveryX3SpoolDir, f.config.LIDeliveryX3SpoolKeyFile, f.config.LIDeliveryX3SpoolKeyID = "", "", ""
						f.config.LIDeliveryX3SpoolMaxBytes = 0
						f.config.LIDeliveryX3SpoolReplayPolicy = ""
					}
					p := f.open(t)
					require.NoError(t, p.startLIManager())
					end := time.Now().Add(time.Minute).UTC()
					implicit := change == "shorten"
					require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &end, ImplicitDeactivationAllowed: &implicit}))
					task, err := p.liManager.GetTaskDetails(f.xid)
					require.NoError(t, err)
					captureAuthorizationPacket(t, p, f, "retained-before-shortening", 1)
					if journal {
						finalized := p.callLifecycle.Finalize("retained-before-shortening", CallFinalizationProtocolComplete)
						require.True(t, finalized.Finalized)
						require.NoError(t, finalized.Err)
					}
					require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
					require.Eventually(t, func() bool {
						if journal {
							return liDeliveryClient.X3JournalStats().Persisted == 1
						}
						return liDeliveryClient.QueueDepth() == 1
					}, time.Second, time.Millisecond)
					cutoff := time.Now().Add(time.Second).UTC()
					// Install the future end while implicit deactivation is disabled
					// before enabling it, so the enabling commit supplies the cutoff.
					if change == "enable_implicit" {
						require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &cutoff}))
						implicit = true
						require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{ImplicitDeactivationAllowed: &implicit}))
					} else {
						require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &cutoff}))
					}
					current, err := p.liManager.GetTaskDetails(f.xid)
					require.NoError(t, err)
					require.Equal(t, task.ActivationGeneration, current.ActivationGeneration)
					require.True(t, time.Now().Before(cutoff))
					timer := time.NewTimer(time.Until(cutoff))
					defer timer.Stop()
					<-timer.C
					require.Eventually(t, func() bool {
						return liDeliveryClient.QueueDepth() == 0 && (!journal || liDeliveryClient.X3JournalStats().Persisted == 0)
					}, 3*time.Second, time.Millisecond, "the committed cutoff must remove retained work")
					permit, err := liDeliveryClient.PrepareX3(f.xid, f.did, []byte("stale content"), li.DeliveryMetadata{
						StateIncarnation: p.liManager.StateIncarnation(), AdmittedAt: time.Now(), TaskGeneration: task.ActivationGeneration,
						TaskEndAt: end,
					})
					require.ErrorIs(t, err, delivery.ErrExpired, "a stale future packet cutoff cannot authorize fresh work")
					require.Nil(t, permit)
					require.NoError(t, p.Shutdown())
				})
			}
		})
	}
}
