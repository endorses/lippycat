//go:build (processor || tap || all) && li

package processor

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestLIProducerCarriesCallIncarnationToEveryReorderDestination(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared-admission-%t", shared), func(t *testing.T) {
			p, xid, filterID := newLIProcessor(t, li.DeliveryX3Only)
			task, err := p.liManager.GetTaskDetails(xid)
			require.NoError(t, err)
			second := uuid.New()
			require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: second, Address: "127.0.0.1", Port: 2, X3Enabled: true}))
			destinations := append(task.DestinationIDs, second)
			require.NoError(t, p.liManager.ModifyTask(xid, &li.TaskModification{DestinationIDs: &destinations}))
			feedIncomingCallSignalling(p, filterID)

			config := delivery.DefaultConfig()
			certDir := filepath.Join("..", "..", "..", "test", "testcerts", "li")
			config.TLSCertFile = filepath.Join(certDir, "delivery-client-cert.pem")
			config.TLSKeyFile = filepath.Join(certDir, "delivery-client-key.pem")
			config.TLSCAFile = filepath.Join(certDir, "ca-cert.pem")
			manager, err := delivery.NewManager(config)
			require.NoError(t, err)
			client := delivery.NewClient(manager, delivery.DefaultClientConfig())
			require.NoError(t, client.Err())
			previousManager, previousClient := liDeliveryMgr, liDeliveryClient
			liDeliveryMgr, liDeliveryClient = manager, client
			var buffers []*delivery.ReorderBuffer
			t.Cleanup(func() {
				for n, buffer := range buffers {
					liReorderBuffers.Delete(fmt.Sprintf("%s-%s", xid, destinations[n]))
					buffer.Stop()
					buffer.Wait()
				}
				client.Stop()
				manager.Stop()
				liDeliveryMgr, liDeliveryClient = previousManager, previousClient
			})
			output := make(chan delivery.ReorderEntry, len(destinations))
			for _, did := range destinations {
				dest, err := p.liManager.GetDestination(did)
				require.NoError(t, err)
				require.NoError(t, manager.AddDestination(dest))
				buffer := delivery.NewCallAwareReorderBuffer(func(entry delivery.ReorderEntry) { output <- entry }, time.Hour)
				buffers = append(buffers, buffer)
				liReorderBuffers.Store(fmt.Sprintf("%s-%s", xid, did), buffer)
			}
			admission, err := p.callLifecycle.Admit(dirCallID)
			require.NoError(t, err)
			defer admission.Release()
			var borrowed *CallAdmission
			if shared {
				borrowed = admission
			} else {
				admission.Release()
			}
			packet := dirRTPPacket(9, dirCoreAddr, dirCorePort, dirGWAddr, dirGWPort)
			p.processLIPacketWithAdmission(packet, nil, []string{filterID}, borrowed)
			for range destinations {
				select {
				case entry := <-output:
					require.Equal(t, admission.Incarnation(), entry.Metadata.CallIncarnation)
					require.NotEqual(t, uuid.Nil, entry.Metadata.CallIncarnation)
					require.Equal(t, admission.Generation(), entry.Metadata.CallGeneration)
					require.Equal(t, dirCallID, entry.CallID)
				case <-time.After(time.Second):
					t.Fatal("producer did not reach destination reorder buffer")
				}
			}
			if shared {
				p.callLifecycle.mu.Lock()
				inflight := admission.call.inflight
				p.callLifecycle.mu.Unlock()
				require.Equal(t, uint64(1), inflight, "LI must not release the packet/PCAP owner's admission")
			}
		})
	}
}
