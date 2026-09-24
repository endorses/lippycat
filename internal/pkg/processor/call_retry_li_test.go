//go:build (processor || tap || all) && li

package processor

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const liRetryCallID = "li-retry@example.invalid"

func retrySIPPacket(method string, code uint32, cseq uint64, branch string, mediaPort uint32) *data.CapturedPacket {
	startLine := "INVITE " + dirTargetURI + " SIP/2.0"
	if code != 0 {
		startLine = fmt.Sprintf("SIP/2.0 %d response", code)
	}
	sdp := ""
	if mediaPort != 0 {
		sdp = dirSDP(dirGWAddr, fmt.Sprint(mediaPort))
	}
	fromTag := "caller"
	if strings.Contains(branch, "new-generation") {
		fromTag = "fresh-caller"
	}
	raw := fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP gw.example.invalid;branch=%s\r\nCall-ID: %s\r\nCSeq: %d INVITE\r\nFrom: <%s>;tag=%s\r\nTo: <%s>\r\nContent-Type: application/sdp\r\n\r\n%s", startLine, branch, liRetryCallID, cseq, dirRemoteURI, fromTag, dirTargetURI, sdp)
	return &data.CapturedPacket{
		TimestampNs:    time.Now().UnixNano(),
		Data:           []byte(raw),
		CaptureLength:  uint32(len(raw)),
		OriginalLength: uint32(len(raw)),
		LinkType:       uint32(layers.LinkTypeEthernet),
		Metadata: &data.PacketMetadata{
			SrcIp: dirCoreAddr, DstIp: dirGWAddr, SrcPort: 5060, DstPort: 5060, Protocol: "SIP",
			Sip: &data.SIPMetadata{CallId: liRetryCallID, Method: method, CseqMethod: "INVITE", CseqNumber: cseq, ViaBranch: branch, ResponseCode: code,
				FromUser: "caller", ToUser: "callee", FromUri: dirRemoteURI, ToUri: dirTargetURI, FromTag: fromTag,
				MediaPorts: mediaPortsForRetry(mediaPort)},
		},
	}
}

func mediaPortsForRetry(port uint32) []uint32 {
	if port == 0 {
		return nil
	}
	return []uint32{port}
}

func retryRTPPacket(ssrc uint32, port uint32) *data.CapturedPacket {
	raw := make([]byte, 172)
	raw[0], raw[1] = 0x80, 104
	binary.BigEndian.PutUint32(raw[8:12], ssrc)
	return &data.CapturedPacket{
		TimestampNs:    time.Now().UnixNano(),
		Data:           raw,
		CaptureLength:  uint32(len(raw)),
		OriginalLength: uint32(len(raw)),
		LinkType:       uint32(layers.LinkTypeEthernet),
		Metadata: &data.PacketMetadata{
			SrcIp: dirCoreAddr, DstIp: dirGWAddr, SrcPort: 35448, DstPort: port, Protocol: "RTP",
			Sip: &data.SIPMetadata{CallId: liRetryCallID, FromUser: "caller", ToUser: "callee"},
			Rtp: &data.RTPMetadata{Ssrc: ssrc, Sequence: 1, PayloadType: 104},
		},
	}
}

func startRetryMDF(t *testing.T, p *Processor, filterID string) (uuid.UUID, <-chan *x2x3.PDU) {
	t.Helper()
	certDir := "../../../test/testcerts/li"
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "mdf-server-cert.pem"), filepath.Join(certDir, "mdf-server-key.pem"))
	require.NoError(t, err)
	ca, err := os.ReadFile(filepath.Join(certDir, "ca-cert.pem"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca))
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	received := make(chan *x2x3.PDU, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				for {
					pdu, err := x2x3.ReadPDU(conn)
					if err != nil {
						return
					}
					received <- pdu
				}
			}()
		}
	}()
	transport := delivery.DefaultConfig()
	transport.TLSCertFile = filepath.Join(certDir, "delivery-client-cert.pem")
	transport.TLSKeyFile = filepath.Join(certDir, "delivery-client-key.pem")
	transport.TLSCAFile = filepath.Join(certDir, "ca-cert.pem")
	liDeliveryMgr, err = delivery.NewManager(transport)
	require.NoError(t, err)
	liDeliveryClient = delivery.NewClient(liDeliveryMgr, delivery.DefaultClientConfig())
	require.NoError(t, liDeliveryClient.Err())
	xid, err := uuid.Parse(strings.TrimSuffix(strings.TrimPrefix(filterID, "li-"), "-0"))
	require.NoError(t, err)
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Len(t, task.DestinationIDs, 1)
	require.NoError(t, replaceLIDeliveryDestination(liDeliveryMgr, liDeliveryClient, &li.Destination{
		DID: task.DestinationIDs[0], Address: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port,
		X3Enabled: true, ProtocolType: "X3Only",
	}))
	liDeliveryClient.Start()
	return xid, received
}

func requireRetryX3(t *testing.T, received <-chan *x2x3.PDU, xid uuid.UUID, ssrc uint32) {
	t.Helper()
	select {
	case pdu := <-received:
		require.NotNil(t, pdu)
		require.Equal(t, x2x3.PDUTypeX3, pdu.Header.Type)
		require.Equal(t, xid, pdu.Header.XID)
		require.Equal(t, x2x3.PayloadFormatRTP, pdu.Header.PayloadFormat)
		require.GreaterOrEqual(t, len(pdu.Payload), 12)
		require.Equal(t, ssrc, binary.BigEndian.Uint32(pdu.Payload[8:12]))
	case <-time.After(3 * time.Second):
		t.Fatalf("MDF did not receive authorized X3 content: delivery=%+v", liDeliveryClient.Stats())
	}
}

func feedRetryPacket(p *Processor, filterID string, packet *data.CapturedPacket, media bool) {
	packet.MatchedFilterIds = []string{filterID}
	if media {
		packet.InheritedMatchedFilterIds = []string{filterID}
	} else {
		packet.DirectMatchedFilterIds = []string{filterID}
	}
	p.processBatch(source.FromProtoBatch(&data.PacketBatch{
		HunterId: "synthetic-retry-hunter",
		Packets:  []*data.CapturedPacket{packet},
	}))
}

func TestLIRetry503PreservesX3AndIsolatesRestart(t *testing.T) {
	for _, pcapEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("pcap_enabled_%t", pcapEnabled), func(t *testing.T) {
			p, filterID := newFinalizationReproductionProcessor(t, pcapEnabled)
			xid, received := startRetryMDF(t, p, filterID)
			monitor := p.sessionOutputManager.monitor.(*CallCompletionMonitor)
			monitor.config.GracePeriod = time.Nanosecond
			before := p.getLIEncodingStats()

			feedRetryPacket(p, filterID, retrySIPPacket("INVITE", 0, 1, "z9hG4bK-first", 0), false)
			feedRetryPacket(p, filterID, retrySIPPacket("RESPONSE", 503, 1, "z9hG4bK-first", 0), false)
			monitor.checkEndedCalls()
			monitor.processPendingClose()
			require.False(t, p.callLifecycle.IsFinalized(liRetryCallID), "a matched 503 must leave X3 admission open")

			feedRetryPacket(p, filterID, retrySIPPacket("INVITE", 0, 2, "z9hG4bK-retry", 0), false)
			feedRetryPacket(p, filterID, retrySIPPacket("RESPONSE", 200, 2, "z9hG4bK-retry", 18000), false)
			feedRetryPacket(p, filterID, retryRTPPacket(0x12345678, 18000), true)
			afterRetry := p.getLIEncodingStats()
			require.Equal(t, before.X3Encoded+1, afterRetry.X3Encoded, "answered retry media must enter authorized X3 encoding")
			requireRetryX3(t, received, xid, 0x12345678)
			require.False(t, p.callLifecycle.IsFinalized(liRetryCallID))

			oldAdmission, err := p.callLifecycle.Admit(liRetryCallID)
			require.NoError(t, err)
			oldGeneration := oldAdmission.Generation()
			oldAdmission.Release()
			require.True(t, p.callLifecycle.Finalize(liRetryCallID, CallFinalizationProtocolComplete).Finalized)
			feedRetryPacket(p, filterID, retrySIPPacket("INVITE", 0, 3, "z9hG4bK-new-generation", 0), false)
			newAdmission, err := p.callLifecycle.Admit(liRetryCallID)
			require.NoError(t, err)
			require.NotEqual(t, oldGeneration, newAdmission.Generation())
			newAdmission.Release()
			_, err = p.callLifecycle.AdmitGeneration(liRetryCallID, oldGeneration)
			require.True(t, IsCallFinalized(err), "queued old-generation X3 cannot attach to the restarted call")

			feedRetryPacket(p, filterID, retrySIPPacket("RESPONSE", 200, 2, "z9hG4bK-retry", 18000), false)
			require.Equal(t, afterRetry.X3Encoded, p.getLIEncodingStats().X3Encoded, "old response must not restore an SDP endpoint")
			feedRetryPacket(p, filterID, retrySIPPacket("RESPONSE", 200, 3, "z9hG4bK-new-generation", 19000), false)
			feedRetryPacket(p, filterID, retryRTPPacket(0x12345678, 18000), true)
			require.Equal(t, afterRetry.X3Encoded, p.getLIEncodingStats().X3Encoded, "old media must stay outside X3 after the fresh answer")
			feedRetryPacket(p, filterID, retryRTPPacket(0x87654321, 19000), true)
			require.Equal(t, afterRetry.X3Encoded+1, p.getLIEncodingStats().X3Encoded, "fresh authorized media must enter X3")
			requireRetryX3(t, received, xid, 0x87654321)
		})
	}
}
