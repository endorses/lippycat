//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Exercise the same decoded-transport metadata projection and LI admission used
// by hunter batches and standalone tap, then read the actual TLS MDF products.
func TestProcessorSIPEmissionCoverageAndContentAdmission(t *testing.T) {
	for _, deliveryType := range []li.DeliveryType{li.DeliveryX2Only, li.DeliveryX2andX3, li.DeliveryX3Only} {
		t.Run(fmt.Sprint(deliveryType), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			address := listener.Addr().String()
			port := listener.Addr().(*net.TCPAddr).Port
			require.NoError(t, listener.Close())
			fixture := &persistentProcessorFixture{address: address}
			products := fixture.listenMDF(t)
			certDir := filepath.Join("..", "..", "..", "test", "testcerts", "li")
			p, err := newTestProcessor(t, Config{
				ProcessorID: "sip-coverage", ListenAddr: "localhost:0", MaxHunters: 1, LIEnabled: true,
				LIDeliveryTLSCertFile: filepath.Join(certDir, "delivery-client-cert.pem"),
				LIDeliveryTLSKeyFile:  filepath.Join(certDir, "delivery-client-key.pem"),
				LIDeliveryTLSCAFile:   filepath.Join(certDir, "ca-cert.pem"),
			})
			require.NoError(t, err)
			p.ctx, p.cancel = context.WithCancel(context.Background())
			require.NoError(t, p.startLIManager())
			did, xid := uuid.New(), uuid.New()
			require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, X3Enabled: true}))
			require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: deliveryType}))
			filterID := "li-" + xid.String() + "-0"
			process := func(raw []byte, filters []string) {
				ev, parseErr := sip.Parse(raw, sip.ParseOptions{})
				method, status := "SERVICE", uint32(0)
				if parseErr == nil {
					method, status = ev.Method, uint32(ev.ResponseCode)
				}
				captured := &data.CapturedPacket{
					Data: liTestSIPFrame(t, raw, true), LinkType: uint32(layers.LinkTypeEthernet), TimestampNs: time.Now().UnixNano(),
					MatchedFilterIds: filters, DirectMatchedFilterIds: filters,
					Metadata: &data.PacketMetadata{SrcIp: "192.0.2.1", DstIp: "192.0.2.2", SrcPort: 5060, DstPort: 5060, Protocol: "SIP", Sip: &data.SIPMetadata{CallId: "coverage", Method: method, ResponseCode: status, CseqMethod: "SERVICE", FromUri: dirTargetURI, ToUri: dirRemoteURI}},
				}
				p.processBatch(source.FromProtoBatch(&data.PacketBatch{HunterId: "local", Packets: []*data.CapturedPacket{captured}}))
			}
			before := p.getLIEncodingStats()
			starts := []string{"SIP/2.0 100 Trying", "SIP/2.0 180 Ringing", "SIP/2.0 183 Session Progress", "SIP/2.0 302 Moved Temporarily", "SERVICE sip:bob@example.test SIP/2.0", "SIP/2.0 200 OK", "SIP/2.0 486 Busy Here", "MESSAGE sip:bob@example.test SIP/2.0"}
			var correlation uint64
			for i, start := range starts {
				contentType := "text/plain"
				if i == len(starts)-1 {
					contentType = "application/vnd.3gpp.sms"
				}
				raw := []byte(start + "\r\nCall-ID: coverage\r\nFrom: <" + dirTargetURI + ">\r\nTo: <" + dirRemoteURI + ">\r\nCSeq: 1 SERVICE\r\nContent-Type: " + contentType + "\r\nContent-Length: 6\r\n\r\nsecret")
				process(raw, []string{filterID})
				if deliveryType == li.DeliveryX3Only {
					continue
				}
				select {
				case pdu := <-products:
					require.Equal(t, x2x3.PDUTypeX2, pdu.Header.Type)
					require.Equal(t, x2x3.PayloadFormatSIP, pdu.Header.PayloadFormat)
					require.Equal(t, xid, pdu.Header.XID)
					if i == 0 {
						correlation = pdu.Header.CorrelationID
					}
					require.Equal(t, correlation, pdu.Header.CorrelationID)
					require.EqualValues(t, i, binary.BigEndian.Uint32(x2x3.FindAttribute(pdu.Attributes, x2x3.AttrSequenceNumber).Value))
					require.Equal(t, []byte{192, 0, 2, 1}, x2x3.FindAttribute(pdu.Attributes, x2x3.AttrSourceIPv4).Value)
					require.Equal(t, []byte{192, 0, 2, 2}, x2x3.FindAttribute(pdu.Attributes, x2x3.AttrDestIPv4).Value)
					if deliveryType == li.DeliveryX2Only {
						parsed, err := sip.Parse(pdu.Payload, sip.ParseOptions{})
						require.NoError(t, err)
						require.Equal(t, start, parsed.StartLine)
						require.Empty(t, parsed.Body)
						require.Equal(t, "0", parsed.Headers["content-length"])
						require.NotContains(t, string(pdu.Payload), "secret")
					} else {
						require.Equal(t, raw, pdu.Payload)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("admitted signaling did not reach MDF")
				}
			}
			expected := uint64(len(starts))
			if deliveryType == li.DeliveryX3Only {
				expected = 0
			}
			require.Equal(t, before.X2Encoded+expected, p.getLIEncodingStats().X2Encoded)
			require.Equal(t, before.X3Encoded, p.getLIEncodingStats().X3Encoded, "SIP expansion must not create CC")
			valid := []byte("SERVICE sip:bob@example.test SIP/2.0\r\nCall-ID: coverage\r\nContent-Length: 0\r\n\r\n")
			process(valid, []string{"li-unauthorized-0"})
			process(valid, nil)
			process([]byte("SIP/2.0 700 Invalid\r\nContent-Length: 0\r\n\r\n"), []string{filterID})
			process([]byte("SERVICE sip:bob@example.test SIP/2.0\r\nContent-Length: 6\r\n\r\nx"), []string{filterID})
			process([]byte("malformed\r\nSERVICE sip:bob@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n"), []string{filterID})
			process([]byte("SERVICE sip:bob@example.test SIP/2.0\r\n\r\n"), []string{filterID})
			process([]byte("SERVICE sip:bob@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n"), []string{filterID})
			process([]byte("SERVICE sip:bob@example.test SIP/2.0\r\nCall-ID: mismatched\r\nContent-Length: 0\r\n\r\n"), []string{filterID})
			require.Equal(t, before.X2Encoded+expected, p.getLIEncodingStats().X2Encoded)
			require.NoError(t, p.liManager.DeactivateTask(xid))
			process(valid, []string{filterID})
			require.Equal(t, before.X2Encoded+expected, p.getLIEncodingStats().X2Encoded, "revoked filter cannot authorize encoding")
			require.Zero(t, liDeliveryClient.QueueDepth(), "every expected product was delivered and no forbidden product was queued")
			select {
			case product := <-products:
				t.Fatalf("unexpected product after rejected input: %v", product.Header)
			default:
			}
			require.NoError(t, p.Shutdown())
		})
	}
}
