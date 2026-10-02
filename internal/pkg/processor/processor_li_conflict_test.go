//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x1"
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
	for _, partial := range []bool{false, true} {
		for _, journal := range []bool{false, true} {
			name := "memory"
			if journal {
				name = "journal"
			}
			t.Run(fmt.Sprintf("%s/partial=%t", name, partial), func(t *testing.T) {
				f := newPersistentProcessorFixture(t)
				if partial {
					f.extraDID = uuid.New()
					f.extraTarget = "sip:removed@example.invalid"
					f.includeExtraScope = true
				}
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
				f.partialSnapshot = partial
				f.includeExtraScope = false
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
				if partial {
					current, err := p.liManager.GetTaskDetails(f.xid)
					require.NoError(t, err)
					require.Equal(t, before.StartTime, current.StartTime)
					require.Equal(t, before.EndTime, current.EndTime)
					require.Len(t, current.Targets, 1)
					require.Equal(t, []uuid.UUID{f.did}, current.DestinationIDs)
					_, err = p.liManager.GetDestination(f.extraDID)
					require.NoError(t, err, "removed task DID must remain globally configured")
					products := f.listenMDF(t)
					// Stale removed filters cannot admit a packet for the withdrawn target.
					removed := dirSIPPacket("INVITE sip:remote@example.invalid SIP/2.0", 0, f.extraTarget, "sip:remote@example.invalid", "", "")
					removed.VoIPData.CallID = "removed-target"
					removed.RawData = []byte(strings.ReplaceAll(string(removed.RawData), dirCallID, "removed-target"))
					removed.Timestamp = time.Now().UTC()
					p.processLIPacketWithProvenance(removed, []string{"li-" + f.xid.String() + "-1"}, nil)
					allowed := dirSIPPacket("INVITE sip:remote@example.invalid SIP/2.0", 0, f.target, "sip:remote@example.invalid", "", "")
					allowed.VoIPData.CallID = "narrowed-target"
					allowed.RawData = []byte(strings.ReplaceAll(string(allowed.RawData), dirCallID, "narrowed-target"))
					allowed.Timestamp = time.Now().UTC()
					p.processLIPacketWithProvenance(allowed, []string{filterID}, nil)
					captureAuthorizationPacket(t, p, f, "narrowed-target", 2)
					require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
					select {
					case product := <-products:
						require.Equal(t, x2x3.PDUTypeX2, product.Header.Type)
					case <-time.After(5 * time.Second):
						t.Fatal("remaining target must deliver X2")
					}
					require.Eventually(t, func() bool { return liDeliveryClient.DestinationStats()[f.did].X2Sent == 1 }, 5*time.Second, time.Millisecond)
					stats := liDeliveryClient.DestinationStats()
					require.Zero(t, stats[f.did].X3Sent)
					require.Zero(t, stats[f.extraDID].X2Sent)
					require.Zero(t, stats[f.extraDID].X3Sent)
					require.Zero(t, stats[f.extraDID].X2QueueDepth)
					require.Zero(t, stats[f.extraDID].X3QueueDepth)
				}
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

// Exercise incoming XML conversion and the real processor's manager using the
// production X1 server and authenticated client certificates.
type processorConflictTaskAdapter struct{ manager *li.Manager }

func (a processorConflictTaskAdapter) ActivateTask(task *x1.Task) error {
	return a.manager.ActivateTaskX1(task)
}
func (a processorConflictTaskAdapter) DeactivateTask(xid uuid.UUID) error {
	return a.manager.DeactivateTaskX1(xid)
}
func (a processorConflictTaskAdapter) ModifyTask(xid uuid.UUID, mod *x1.TaskModification) error {
	return a.manager.ModifyTaskX1(xid, mod)
}
func (a processorConflictTaskAdapter) GetTaskDetails(xid uuid.UUID) (*x1.Task, error) {
	return a.manager.GetTaskDetailsX1(xid)
}

func processorConflictX1Client(t *testing.T, p *Processor) func(string, string) string {
	t.Helper()
	certDir := filepath.Join("..", "..", "..", "test", "testcerts", "li")
	server := x1.NewServer(x1.ServerConfig{ListenAddr: "127.0.0.1:0", TLSCertFile: filepath.Join(certDir, "x1-server-cert.pem"), TLSKeyFile: filepath.Join(certDir, "x1-server-key.pem"), TLSCAFile: filepath.Join(certDir, "ca-cert.pem"), NEIdentifier: "test-ne"}, nil, processorConflictTaskAdapter{manager: p.liManager})
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- server.StartReady(context.Background(), ready) }()
	require.NoError(t, <-ready)
	t.Cleanup(func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) })
	certificate, err := tls.LoadX509KeyPair(filepath.Join(certDir, "admf-client-cert.pem"), filepath.Join(certDir, "admf-client-key.pem"))
	require.NoError(t, err)
	ca, err := os.ReadFile(filepath.Join(certDir, "ca-cert.pem"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca))
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	return func(operation, details string) string {
		raw := fmt.Sprintf(`<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><x1RequestMessage xsi:type="%sRequest"><admfIdentifier>test-admf</admfIdentifier><neIdentifier>test-ne</neIdentifier><version>v1.22.1</version><x1TransactionId>%s</x1TransactionId><admfTimestamp>2026-10-01T00:00:00.000000Z</admfTimestamp>%s</x1RequestMessage></X1Request>`, operation, uuid.New(), details)
		response, err := client.Post("https://"+server.Addr()+"/", "application/xml", strings.NewReader(raw))
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		return string(body)
	}
}

func TestProcessorDisarmedRenewalAndExplicitRecovery(t *testing.T) {
	for _, journal := range []bool{false, true} {
		t.Run(fmt.Sprintf("journal=%t", journal), func(t *testing.T) {
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
			request := processorConflictX1Client(t, p)
			originalTarget := f.target
			require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &f.endTime}))
			original, err := p.liManager.GetTaskDetails(f.xid)
			require.NoError(t, err)
			filterID := "li-" + f.xid.String() + "-0"
			sip := dirSIPPacket("INVITE sip:remote@example.invalid SIP/2.0", 0, originalTarget, "sip:remote@example.invalid", "", "")
			sip.Timestamp = time.Now().UTC()
			p.processLIPacketWithProvenance(sip, []string{filterID}, nil)
			captureAuthorizationPacket(t, p, f, dirCallID, 1)
			if journal {
				require.NoError(t, p.callLifecycle.Finalize(dirCallID, CallFinalizationProtocolComplete).Err)
			}
			require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
			require.Eventually(t, func() bool {
				if journal {
					return liDeliveryClient.JournalStats().Persisted > 0 && liDeliveryClient.X3JournalStats().Persisted > 0
				}
				stats := liDeliveryClient.DestinationStats()[f.did]
				return stats.X2QueueDepth > 0 && stats.X3QueueDepth > 0
			}, 5*time.Second, time.Millisecond)
			f.mu.Lock()
			f.target = "sip:disjoint@example.invalid"
			f.mu.Unlock()
			require.Eventually(t, func() bool {
				task, err := p.liManager.GetTaskDetails(f.xid)
				return err == nil && task.Definition.ConflictDisarmed
			}, 5*time.Second, time.Millisecond)
			disarmed, err := p.liManager.GetTaskDetails(f.xid)
			require.NoError(t, err)
			renewedEnd := original.EndTime.Add(time.Hour)
			body := request("ModifyTask", fmt.Sprintf(`<taskDetails><xId>%s</xId><listOfMediationDetails><mediationDetails><LIID>renewal</LIID><deliveryType>HI2andHI3</deliveryType><EndTime>%s</EndTime></mediationDetails></listOfMediationDetails></taskDetails>`, f.xid, renewedEnd.Format(time.RFC3339Nano)))
			require.Contains(t, body, "modification not allowed")
			after, err := p.liManager.GetTaskDetails(f.xid)
			require.NoError(t, err)
			require.Equal(t, disarmed, after)
			// Attempts under the retained old filter cannot enqueue fresh product.
			sip.VoIPData.CallID = "disarmed-attempt"
			sip.RawData = []byte(strings.ReplaceAll(string(sip.RawData), dirCallID, "disarmed-attempt"))
			sip.Timestamp = time.Now().UTC()
			p.processLIPacketWithProvenance(sip, []string{filterID}, nil)
			captureAuthorizationPacket(t, p, f, "disarmed-attempt", 2)
			require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
			require.Eventually(t, func() bool {
				return liDeliveryClient.QueueDepth() == 0 && (!journal || (liDeliveryClient.JournalStats().Persisted == 0 && liDeliveryClient.X3JournalStats().Persisted == 0))
			}, 5*time.Second, time.Millisecond)
			require.False(t, p.liManager.ReplayTaskAuthorized(f.xid, original.ActivationGeneration))
			body = request("DeactivateTask", fmt.Sprintf(`<xId>%s</xId>`, f.xid))
			require.NotContains(t, body, "<errorCode>")
			// The task's authority is deliberately restored through the complete X1
			// activation operation; the matching snapshot alone cannot recover it.
			f.mu.Lock()
			f.target = originalTarget
			f.mu.Unlock()
			body = request("ActivateTask", fmt.Sprintf(`<taskDetails><xId>%s</xId><targetIdentifiers><targetIdentifier><sipUri>%s</sipUri></targetIdentifier></targetIdentifiers><deliveryType>X2andX3</deliveryType><listOfDIDs><dId>%s</dId></listOfDIDs><implicitDeactivationAllowed>true</implicitDeactivationAllowed><listOfMediationDetails><mediationDetails><LIID>recovered</LIID><deliveryType>HI2andHI3</deliveryType><StartTime>%s</StartTime><EndTime>%s</EndTime></mediationDetails></listOfMediationDetails></taskDetails>`, f.xid, originalTarget, f.did, original.StartTime.Format(time.RFC3339Nano), original.EndTime.Format(time.RFC3339Nano)))
			require.NotContains(t, body, "<errorCode>")
			recovered, err := p.liManager.GetTaskDetails(f.xid)
			require.NoError(t, err)
			require.Equal(t, li.TaskStatusActive, recovered.Status)
			require.Greater(t, recovered.ActivationGeneration, disarmed.ActivationGeneration)
			require.False(t, p.liManager.ReplayTaskAuthorized(f.xid, original.ActivationGeneration))
			products := f.listenMDF(t)
			fresh := dirSIPPacket("INVITE sip:remote@example.invalid SIP/2.0", 0, originalTarget, "sip:remote@example.invalid", "", "")
			fresh.VoIPData.CallID = "recovered-call"
			fresh.RawData = []byte(strings.ReplaceAll(string(fresh.RawData), dirCallID, "recovered-call"))
			fresh.Timestamp = time.Now().UTC()
			p.processLIPacketWithProvenance(fresh, []string{filterID}, nil)
			captureAuthorizationPacket(t, p, f, "recovered-call", 3)
			if journal {
				require.NoError(t, p.callLifecycle.Finalize("recovered-call", CallFinalizationProtocolComplete).Err)
			}
			require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
			seen := map[x2x3.PDUType]bool{}
			for range 2 {
				select {
				case product := <-products:
					require.Equal(t, f.xid, product.Header.XID)
					seen[product.Header.Type] = true
				case <-time.After(5 * time.Second):
					t.Fatal("fresh generation must deliver X2 and X3")
				}
			}
			require.True(t, seen[x2x3.PDUTypeX2])
			require.True(t, seen[x2x3.PDUTypeX3])
			require.Eventually(t, func() bool {
				stats := liDeliveryClient.DestinationStats()[f.did]
				return stats.X2Sent == 1 && stats.X3Sent == 1
			}, 5*time.Second, time.Millisecond)
			require.NoError(t, p.Shutdown())
			if journal {
				restarted := f.open(t)
				require.NoError(t, restarted.startLIManager())
				require.False(t, restarted.liManager.ReplayTaskAuthorized(f.xid, original.ActivationGeneration))
				require.Zero(t, liDeliveryClient.JournalStats().Persisted)
				require.Zero(t, liDeliveryClient.X3JournalStats().Persisted)
			}
		})
	}
}
