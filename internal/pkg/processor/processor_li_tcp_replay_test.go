//go:build (tap || all) && li && linux

package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type replayTargetFilter struct{}

func (replayTargetFilter) MatchPacket(packet gopacket.Packet) bool {
	app := packet.ApplicationLayer()
	if app == nil {
		return false
	}
	event, err := sip.Parse(app.Payload(), sip.ParseOptions{})
	return err == nil && (event.FromURI == dirTargetURI || event.ToURI == dirTargetURI)
}

// Replay on-disk synthetic pcaps through the real assembler and tap TCP handler,
// then the processor batch/admission pipeline and the actual TLS MDF transport.
func TestProcessorTapReplaysTCPReusePCAPToMDF(t *testing.T) {
	for _, trailingRST := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("trailing-RST=%t/reverse=%t", trailingRST, reverse), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				address, port := listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
				require.NoError(t, listener.Close())
				mdf := (&persistentProcessorFixture{address: address}).listenMDF(t)
				cfg := storageKeyStartupConfig(t)
				cfg.ProcessorID, cfg.ListenAddr, cfg.MaxHunters = "tcp-replay", "localhost:0", 1
				p, err := newTestProcessor(t, cfg)
				require.NoError(t, err)
				p.ctx, p.cancel = context.WithCancel(context.Background())
				require.NoError(t, p.startLIManager())
				did, xid := uuid.New(), uuid.New()
				require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, X3Enabled: true}))
				require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2andX3}))
				filterID := "li-" + xid.String() + "-0"
				path := filepath.Join(t.TempDir(), "tcp-reuse.pcap")
				expected := writeTCPReusePCAP(t, path, trailingRST, reverse)
				injected := make(chan source.InjectedPacket, 16)
				handler := voip.NewTapTCPHandler(injected)
				handler.SetApplicationFilter(replayTargetFilter{})
				t.Cleanup(handler.Close)
				streamConfig := voip.DefaultConfig()
				streamConfig.MaxStreams = 2
				factory := voip.NewSipStreamFactoryWithConfig(t.Context(), handler, *streamConfig, nil)
				assembler := capture.NewTCPAssembler(factory)
				t.Cleanup(func() { assembler.FlushAll(); require.NoError(t, factory.Shutdown()) })
				file, err := os.Open(path)
				require.NoError(t, err)
				reader, err := pcapgo.NewReader(file)
				require.NoError(t, err)
				for {
					raw, info, readErr := reader.ReadPacketData()
					if readErr == io.EOF {
						break
					}
					require.NoError(t, readErr)
					packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
					require.Nil(t, packet.ErrorLayer())
					assembler.Assemble(packet.NetworkLayer().NetworkFlow(), packet.Layer(layers.LayerTypeTCP).(*layers.TCP), info.Timestamp)
				}
				require.NoError(t, file.Close())
				require.Eventually(t, func() bool { return len(injected) == len(expected) }, time.Second, time.Millisecond, "both directions of both connections must reach the tap handler")
				assembler.FlushAll()
				require.NoError(t, factory.Shutdown())
				handler.Close()
				if trailingRST {
					require.EqualValues(t, 1, assembler.OrphanControls())
				} else {
					require.Zero(t, assembler.OrphanControls())
				}
				before := p.getLIEncodingStats()
				correlations := make(map[string]uint64)
				counts := make(map[string]uint32)
				for range len(expected) {
					packet := <-injected
					captured := capturedTapReplayPacket(t, packet, filterID)
					parsed, err := sip.Parse(packet.PacketInfo.Packet.ApplicationLayer().Payload(), sip.ParseOptions{})
					require.NoError(t, err)
					key := parsed.CallID + "/" + parsed.StartLine
					want, found := expected[key]
					require.True(t, found, "unexpected reconstructed message %s", key)
					p.processBatch(source.FromProtoBatch(&data.PacketBatch{HunterId: "local", Packets: []*data.CapturedPacket{captured}}))
					select {
					case product := <-mdf:
						require.Equal(t, x2x3.PDUTypeX2, product.Header.Type)
						require.Equal(t, x2x3.PayloadFormatSIP, product.Header.PayloadFormat)
						require.Equal(t, xid, product.Header.XID)
						require.Equal(t, want, product.Payload)
						if previous, ok := correlations[parsed.CallID]; ok {
							require.Equal(t, previous, product.Header.CorrelationID)
						} else {
							correlations[parsed.CallID] = product.Header.CorrelationID
						}
						require.Equal(t, counts[parsed.CallID], binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
						counts[parsed.CallID]++
						ip := packet.PacketInfo.Packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
						tcp := packet.PacketInfo.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
						require.Equal(t, []byte(ip.SrcIP.To4()), x2x3.FindAttribute(product.Attributes, x2x3.AttrSourceIPv4).Value)
						require.Equal(t, []byte(ip.DstIP.To4()), x2x3.FindAttribute(product.Attributes, x2x3.AttrDestIPv4).Value)
						require.EqualValues(t, tcp.SrcPort, binary.BigEndian.Uint16(x2x3.FindAttribute(product.Attributes, x2x3.AttrSourcePort).Value))
						require.EqualValues(t, tcp.DstPort, binary.BigEndian.Uint16(x2x3.FindAttribute(product.Attributes, x2x3.AttrDestPort).Value))
					case <-time.After(5 * time.Second):
						t.Fatal("replayed target SIP did not reach MDF")
					}
				}
				require.Len(t, counts, 2)
				require.EqualValues(t, 4, counts["first-call"])
				require.EqualValues(t, 4, counts["second-call"])
				require.NotEqual(t, correlations["first-call"], correlations["second-call"])
				after := p.getLIEncodingStats()
				require.Equal(t, before.X2Encoded+8, after.X2Encoded)
				require.Equal(t, before.X3Encoded, after.X3Encoded, "new signaling coverage must not synthesize CC")
				rtp := dirRTPPacket(42, dirGWAddr, dirGWPort, dirCoreAddr, dirCorePort)
				rtp.Timestamp = time.Now().UTC()
				rtp.VoIPData.CallID = "second-call"
				admission, err := p.callLifecycle.Admit("second-call")
				require.NoError(t, err)
				p.processLIPacketWithAdmission(rtp, nil, []string{filterID}, admission)
				admission.Release()
				require.Equal(t, after.X3Encoded+1, p.getLIEncodingStats().X3Encoded, "RTP encoding stats %+v", p.getLIEncodingStats())
				buffer, found := liReorderBuffers.Load(fmt.Sprintf("%s-%s", xid, did))
				require.True(t, found)
				buffer.(*delivery.ReorderBuffer).Stop()
				buffer.(*delivery.ReorderBuffer).Wait()
				require.EqualValues(t, 1, liDeliveryClient.Stats().X3Queued, "delivery stats %+v / encoding stats %+v", liDeliveryClient.Stats(), p.getLIEncodingStats())
				select {
				case product := <-mdf:
					require.Equal(t, x2x3.PDUTypeX3, product.Header.Type)
					require.Equal(t, xid, product.Header.XID)
					require.Equal(t, correlations["second-call"], product.Header.CorrelationID)
					require.Equal(t, x2x3.PayloadDirectionFromTarget, product.Header.PayloadDirection)
					require.Equal(t, rtp.RawData, product.Payload, "X3 attribution and captured bytes remain intact")
				case <-time.After(5 * time.Second):
					t.Fatal("associated second-call RTP did not reach MDF")
				}
				require.NoError(t, p.liManager.DeactivateTask(xid))
				final := p.getLIEncodingStats()
				p.processLIPacketWithProvenance(rtp, nil, []string{filterID})
				require.Equal(t, final.X3Encoded, p.getLIEncodingStats().X3Encoded, "revoked task cannot authorize media")
				require.NoError(t, p.Shutdown())
			})
		}
	}
}

func capturedTapReplayPacket(t *testing.T, injected source.InjectedPacket, filterID string) *data.CapturedPacket {
	t.Helper()
	packet := injected.PacketInfo.Packet
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	metadata := injected.Metadata
	metadata.SrcIp, metadata.DstIp = ip.SrcIP.String(), ip.DstIP.String()
	metadata.SrcPort, metadata.DstPort = uint32(tcp.SrcPort), uint32(tcp.DstPort)
	metadata.Protocol = "SIP"
	return &data.CapturedPacket{Data: packet.Data(), TimestampNs: packet.Metadata().Timestamp.UnixNano(), LinkType: uint32(injected.PacketInfo.LinkType), Metadata: metadata, MatchedFilterIds: []string{filterID}, DirectMatchedFilterIds: []string{filterID}}
}

func writeTCPReusePCAP(t *testing.T, path string, trailingRST, reverse bool) map[string][]byte {
	t.Helper()
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65536, layers.LinkTypeEthernet))
	at := time.Now().UTC()
	write := func(seq uint32, back bool, flags string, payload []byte) {
		t.Helper()
		src, dst := net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)
		sport, dport := layers.TCPPort(60421), layers.TCPPort(5060)
		if back != reverse {
			src, dst = dst, src
			sport, dport = dport, sport
		}
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		tcp := &layers.TCP{SrcPort: sport, DstPort: dport, Seq: seq, SYN: flags == "syn" || flags == "synack", ACK: flags == "ack" || flags == "synack", FIN: flags == "fin", RST: flags == "rst"}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)))
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()))
		at = at.Add(time.Millisecond)
	}
	expected := make(map[string][]byte)
	for connection, id := range []string{"first-call", "second-call"} {
		reqSeq, respSeq := uint32(100+connection*3000), uint32(200+connection*7000)
		write(reqSeq, false, "syn", nil)
		write(respSeq, true, "synack", nil)
		reqSeq++
		respSeq++
		for _, start := range []string{"INVITE " + dirRemoteURI + " SIP/2.0", "SIP/2.0 100 Trying", "SIP/2.0 183 Session Progress", "SIP/2.0 302 Moved Temporarily"} {
			body := ""
			back := start[:3] == "SIP"
			if !back {
				body = dirSDP(dirGWAddr, dirGWPort)
			} else if start == "SIP/2.0 183 Session Progress" {
				body = dirSDP(dirCoreAddr, dirCorePort)
			}
			contentType := ""
			if body != "" {
				contentType = "Content-Type: application/sdp\r\n"
			}
			raw := []byte(start + "\r\nCall-ID: " + id + "\r\nFrom: <" + dirTargetURI + ">;tag=from\r\nTo: <" + dirRemoteURI + ">\r\nCSeq: 1 INVITE\r\n" + contentType + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
			expected[id+"/"+start] = raw
			if back {
				write(respSeq, true, "ack", raw)
				respSeq += uint32(len(raw))
			} else {
				write(reqSeq, false, "ack", raw)
				reqSeq += uint32(len(raw))
			}
		}
		write(reqSeq, false, "fin", nil)
		write(respSeq, true, "fin", nil)
		if connection == 0 && trailingRST {
			write(respSeq+1, true, "rst", nil)
		}
	}
	require.NoError(t, file.Close())
	return expected
}
