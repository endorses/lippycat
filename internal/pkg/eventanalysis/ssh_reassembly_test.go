package eventanalysis

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/conntrack"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func sshRuntime(t *testing.T, policy eventconfig.SSHPolicy) (*Runtime, *events.Dispatcher, *memorySink) {
	t.Helper()
	producer, err := events.NewLiveProducer("ssh-analysis")
	require.NoError(t, err)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 512, SinkQueueSize: 512, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, dispatcher.Register(sink))
	config := eventconfig.Default()
	config.SSH = &policy
	runtime, err := New(Config{Dispatcher: dispatcher, Policy: &config, Connections: conntrack.Config{IdleTimeout: 5 * time.Second}})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	t.Cleanup(func() {
		runtime.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, dispatcher.Close(ctx))
	})
	return runtime, dispatcher, sink
}

func sshOutput(t *testing.T, dispatcher *events.Dispatcher, sink *memorySink) []events.SSHEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, dispatcher.Flush(ctx))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var result []events.SSHEvent
	for _, event := range sink.events {
		if ssh, ok := event.(events.SSHEvent); ok {
			_, err := protoadapter.ToProto(ssh)
			require.NoError(t, err, "canonical observations must satisfy the wire contract")
			require.True(t, events.HasValidDeliveryIdentity(ssh.Envelope()))
			result = append(result, ssh)
		}
	}
	return result
}

func sshInitialWires(t *testing.T) [2][]byte {
	t.Helper()
	packets, err := eventfixture.SSHMessages()
	require.NoError(t, err)
	var wires [2][]byte
	for _, info := range packets {
		tcp := info.Packet.TransportLayer().(*layers.TCP)
		index := 0
		if tcp.SrcPort == eventfixture.SSHServerPort {
			index = 1
		}
		wires[index] = append(wires[index], tcp.Payload...)
	}
	for i, wire := range wires {
		bannerEnd := bytes.IndexByte(wire, '\n') + 1
		require.Positive(t, bannerEnd)
		require.True(t, bytes.HasPrefix(wire, []byte("SSH-")))
		require.GreaterOrEqual(t, len(wire)-bannerEnd, 5)
		packetEnd := bannerEnd + 4 + int(binary.BigEndian.Uint32(wire[bannerEnd:]))
		require.LessOrEqual(t, packetEnd, len(wire))
		require.EqualValues(t, 20, wire[bannerEnd+5], "the controlled peer's first binary packet is KEXINIT")
		wires[i] = wire[:packetEnd]
	}
	return wires
}

func observeSSHSegment(t *testing.T, runtime *Runtime, source Source, client bool, tcp layers.TCP, payload []byte, at time.Time, transported bool) {
	t.Helper()
	info, err := eventfixture.SSHSegment(client, tcp, payload, at)
	require.NoError(t, err)
	if transported {
		metadata := &data.PacketMetadata{SrcIp: info.Packet.NetworkLayer().NetworkFlow().Src().String(), DstIp: info.Packet.NetworkLayer().NetworkFlow().Dst().String(), SrcPort: uint32(info.Packet.TransportLayer().(*layers.TCP).SrcPort), DstPort: uint32(info.Packet.TransportLayer().(*layers.TCP).DstPort), Transport: "tcp", Protocol: "SSH"}
		require.NoError(t, runtime.ObserveCaptured(source, []*data.CapturedPacket{{Data: info.Packet.Data(), TimestampNs: at.UnixNano(), CaptureLength: uint32(len(info.Packet.Data())), OriginalLength: uint32(len(info.Packet.Data())), LinkType: uint32(info.LinkType), InterfaceName: info.Interface, Metadata: metadata}}))
	} else {
		require.NoError(t, runtime.ObservePacket(source, info))
	}
}

func sshHandshake(t *testing.T, runtime *Runtime, source Source, at time.Time, transported bool) {
	t.Helper()
	observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1000, SYN: true}, nil, at, transported)
	observeSSHSegment(t, runtime, source, false, layers.TCP{Seq: 9000, Ack: 1001, SYN: true, ACK: true}, nil, at.Add(time.Millisecond), transported)
}

func TestSSHCanonicalControlledClientServerRawAndTransported(t *testing.T) {
	packets, err := eventfixture.SSHMessages()
	require.NoError(t, err)
	for _, transported := range []bool{false, true} {
		t.Run(fmt.Sprintf("transported=%t", transported), func(t *testing.T) {
			runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
			source := Source{NodeID: "hunter", CaptureSource: "hunter", CaptureEpoch: "ssh-epoch", InterfaceName: "ssh-fixture0", InputFile: "generated-ssh.pcap", ProcessorNodeIDs: []string{"edge", "central"}}
			for _, info := range packets {
				tcp := *info.Packet.TransportLayer().(*layers.TCP)
				observeSSHSegment(t, runtime, source, tcp.SrcPort == eventfixture.SSHClientPort, tcp, tcp.Payload, info.Packet.Metadata().Timestamp, transported)
			}
			runtime.EOF()
			got := sshOutput(t, dispatcher, sink)
			require.Len(t, got, 4, "encrypted traffic and EOF cannot repeat an initial handshake")
			complete := make(map[events.SSHRole]events.SSHEvent)
			for _, event := range got {
				require.Equal(t, "ssh-analysis", event.Envelope().NodeID)
				require.Equal(t, source.CaptureSource, event.Envelope().Provenance.CaptureSource)
				require.Equal(t, source.InputFile, event.Envelope().Provenance.InputFile)
				require.Equal(t, source.ProcessorNodeIDs, event.Envelope().Provenance.ProcessorNodeIDs)
				require.Equal(t, got[0].Envelope().UID, event.Envelope().UID)
				require.Equal(t, got[0].Envelope().CommunityID, event.Envelope().CommunityID)
				require.False(t, event.Envelope().Partial)
				if event.Status == events.SSHStatusComplete {
					complete[event.Role] = event
					require.Len(t, event.HASSH, 32)
					require.Equal(t, "1.0", event.HASSHVersion)
				}
			}
			require.Len(t, complete, 2)
			require.Equal(t, uint16(eventfixture.SSHClientPort), complete[events.SSHRoleClient].Envelope().Flow.SourcePort)
			require.Equal(t, uint16(eventfixture.SSHServerPort), complete[events.SSHRoleServer].Envelope().Flow.SourcePort)
			require.Equal(t, "lippycat_fixture_client", complete[events.SSHRoleClient].SoftwareVersion)
			require.Equal(t, "lippycat_fixture_server", complete[events.SSHRoleServer].SoftwareVersion)
			sink.mu.Lock()
			var connections []events.ConnEvent
			for _, event := range sink.events {
				if connection, ok := event.(events.ConnEvent); ok {
					connections = append(connections, connection)
				}
			}
			sink.mu.Unlock()
			require.Len(t, connections, 1)
			require.Equal(t, "SSH", connections[0].Service)
			require.Zero(t, runtime.Stats().SSH.ActiveFlows)
			require.Zero(t, runtime.Stats().SSH.ReservedBytes)
		})
	}
}

func TestSSHCanonicalSplitPrefixOutOfOrderFinalByteAndRetransmission(t *testing.T) {
	wires := sshInitialWires(t)
	for _, transported := range []bool{false, true} {
		t.Run(fmt.Sprintf("transported=%t", transported), func(t *testing.T) {
			runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
			source := Source{NodeID: "hunter", CaptureSource: "hunter", CaptureEpoch: "ssh", InterfaceName: "ssh-fixture0"}
			at := eventfixture.BaseTime
			sshHandshake(t, runtime, source, at, transported)
			observeSSHSegment(t, runtime, source, false, layers.TCP{Seq: 9001, ACK: true}, wires[1][:2], at.Add(2*time.Millisecond), transported)
			observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1001, ACK: true}, wires[0][:1], at.Add(3*time.Millisecond), transported)
			observeSSHSegment(t, runtime, source, false, layers.TCP{Seq: 9003, ACK: true}, wires[1][2:], at.Add(4*time.Millisecond), transported)
			split := bytes.IndexByte(wires[0], '\n') + 11
			filtered := source
			filtered.CaptureScope = events.CaptureScopeFiltered
			observeSSHSegment(t, runtime, filtered, true, layers.TCP{Seq: uint32(1001 + split), ACK: true}, wires[0][split:], at.Add(5*time.Millisecond), transported)
			observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1002, ACK: true}, wires[0][1:split], at.Add(6*time.Millisecond), transported)
			observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: uint32(1001 + split), ACK: true}, wires[0][split:], at.Add(7*time.Millisecond), transported)
			got := sshOutput(t, dispatcher, sink)
			require.Len(t, got, 4)
			for _, event := range got {
				if event.Role == events.SSHRoleServer {
					require.Equal(t, at.Add(4*time.Millisecond).UnixNano(), event.Envelope().Timestamp.UnixNano())
				} else if event.Status == events.SSHStatusBanner {
					require.Equal(t, at.Add(6*time.Millisecond).UnixNano(), event.Envelope().Timestamp.UnixNano())
				} else {
					require.Equal(t, at.Add(5*time.Millisecond).UnixNano(), event.Envelope().Timestamp.UnixNano(), "capture mark belongs to the final byte, not the packet that released the queued tail")
					require.Equal(t, events.CaptureScopeFiltered, event.Envelope().CaptureScope)
					require.True(t, event.Envelope().Partial)
				}
			}
		})
	}
}

func TestSSHCanonicalEndpointRolesNeedIndependentEvidence(t *testing.T) {
	wires := sshInitialWires(t)
	for _, proof := range []string{"synack-first", "none", "port22", "simultaneous-open"} {
		t.Run(proof, func(t *testing.T) {
			runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
			source := Source{NodeID: "hunter", CaptureSource: "capture", CaptureEpoch: proof}
			at := eventfixture.BaseTime
			switch proof {
			case "synack-first":
				observeSSHSegment(t, runtime, source, false, layers.TCP{Seq: 9000, Ack: 1001, SYN: true, ACK: true}, nil, at, false)
			case "simultaneous-open":
				observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1000, SYN: true}, nil, at, false)
				observeSSHSegment(t, runtime, source, false, layers.TCP{Seq: 9000, SYN: true}, nil, at, false)
			}
			// Server is first-seen payload in every case; the custom destination
			// port and this assembler direction are deliberately insufficient.
			serverTCP, clientTCP := layers.TCP{Seq: 9001, ACK: true}, layers.TCP{Seq: 1001, ACK: true}
			if proof == "port22" {
				serverTCP.SrcPort, clientTCP.DstPort = 22, 22
			}
			observeSSHSegment(t, runtime, source, false, serverTCP, wires[1], at.Add(time.Millisecond), false)
			observeSSHSegment(t, runtime, source, true, clientTCP, wires[0], at.Add(2*time.Millisecond), false)
			runtime.EOF()
			got := sshOutput(t, dispatcher, sink)
			require.Len(t, got, 4)
			for _, event := range got {
				if proof == "synack-first" {
					require.Equal(t, events.SSHRoleEvidenceTCPSYNACK, event.RoleEvidence)
					if event.Envelope().Flow.SourcePort == eventfixture.SSHServerPort {
						require.Equal(t, events.SSHRoleServer, event.Role)
					} else {
						require.Equal(t, events.SSHRoleClient, event.Role)
					}
				} else {
					require.Equal(t, events.SSHRoleUnknown, event.Role)
					require.Empty(t, event.HASSH)
					if proof == "simultaneous-open" {
						require.Equal(t, events.SSHRoleEvidenceConflict, event.RoleEvidence)
					} else {
						require.Equal(t, events.SSHRoleEvidenceUnknown, event.RoleEvidence)
					}
				}
			}
		})
	}
}

func TestSSHCanonicalSourceEpochIsolationAndTupleReuse(t *testing.T) {
	wire := sshInitialWires(t)[0]
	runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
	at := eventfixture.BaseTime
	source := Source{NodeID: "hunter-a", CaptureSource: "capture", CaptureEpoch: "first", InterfaceName: "ssh-fixture0"}
	sshHandshake(t, runtime, source, at, false)
	split := len(wire) - 15
	observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1001, ACK: true}, wire[:split], at.Add(time.Millisecond), false)
	for i, other := range []Source{
		{NodeID: "hunter-b", CaptureSource: "capture", CaptureEpoch: "first", InterfaceName: "ssh-fixture0"},
		{NodeID: "hunter-a", CaptureSource: "capture", CaptureEpoch: "second", InterfaceName: "ssh-fixture0"},
		{NodeID: "hunter-a", CaptureSource: "capture", CaptureEpoch: "first", InterfaceName: "other"},
	} {
		observeSSHSegment(t, runtime, other, true, layers.TCP{Seq: uint32(1001 + split), ACK: true}, wire[split:], at.Add(time.Duration(i+2)*time.Millisecond), false)
	}
	require.Len(t, sshOutput(t, dispatcher, sink), 1, "another source cannot complete this handshake")
	observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: uint32(1001 + split), ACK: true}, wire[split:], at.Add(5*time.Millisecond), false)
	got := sshOutput(t, dispatcher, sink)
	require.Len(t, got, 2)
	require.Equal(t, events.SSHStatusComplete, got[1].Status)
	// A fresh bare SYN starts a different incarnation even when the prior
	// connection's FIN was not captured. Its role/parser must start afresh.
	observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 100000, SYN: true}, nil, at.Add(6*time.Millisecond), false)
	observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 100001, ACK: true}, wire, at.Add(7*time.Millisecond), false)
	got = sshOutput(t, dispatcher, sink)
	require.Len(t, got, 4)
	require.Equal(t, events.SSHStatusComplete, got[3].Status)
	require.NotEqual(t, got[1].Envelope().EventID, got[3].Envelope().EventID)
	runtime.EOF()
	require.Zero(t, runtime.Stats().SSH.ActiveFlows)
	require.Zero(t, runtime.Stats().SSH.ReservedBytes)
}

func TestSSHCanonicalGapsExpiryAndTerminalStatesCannotRevive(t *testing.T) {
	wire := sshInitialWires(t)[0]
	for _, terminal := range []string{"gap", "expiry", "newkeys", "unsupported", "oversized", "malformed-list", "missing-banner"} {
		t.Run(terminal, func(t *testing.T) {
			runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
			source := Source{NodeID: "hunter", CaptureSource: "capture", CaptureEpoch: terminal}
			at := eventfixture.BaseTime
			sshHandshake(t, runtime, source, at, false)
			bannerEnd := bytes.IndexByte(wire, '\n') + 1
			prefix := wire[:len(wire)-15]
			expected := events.SSHReasonIncomplete
			switch terminal {
			case "newkeys":
				prefix = append(append([]byte(nil), wire[:bannerEnd]...), []byte{0, 0, 0, 12, 10, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...)
				expected = events.SSHReasonNewKeys
			case "unsupported":
				prefix = []byte("SSH-1.5-fixture\r\n")
				expected = events.SSHReasonUnsupportedVersion
			case "oversized":
				prefix = append(append([]byte(nil), wire[:bannerEnd]...), []byte{0, 2, 0, 0, 4}...)
				expected = events.SSHReasonResourceLimit
			case "malformed-list":
				prefix = append([]byte(nil), wire...)
				prefix[bannerEnd+5+17+4] = ',' // Empty first algorithm name.
				expected = events.SSHReasonMalformed
			case "missing-banner":
				prefix = []byte("SSH-")
				expected = events.SSHReasonMissingBanner
			}
			observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1001, ACK: true}, prefix, at.Add(time.Millisecond), false)
			if terminal == "gap" {
				expected = events.SSHReasonGap
				observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: uint32(1001 + len(prefix) + 4), ACK: true}, wire[len(wire)-15:], at.Add(2*time.Millisecond), false)
			}
			if terminal == "expiry" {
				runtime.Expire(at.Add(10 * time.Second))
			} else {
				runtime.EOF()
			}
			got := sshOutput(t, dispatcher, sink)
			require.NotEmpty(t, got)
			require.Equal(t, events.SSHStatusPartial, got[len(got)-1].Status)
			require.Equal(t, expected, got[len(got)-1].Reason)
			for _, event := range got {
				require.Empty(t, event.HASSH)
			}
			require.Zero(t, runtime.Stats().SSH.ReservedBytes)
			if terminal == "expiry" {
				// Tail replay after expiry has no banner or SYN evidence and
				// cannot resurrect the expired half's identification/role.
				observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: uint32(1001 + len(prefix)), ACK: true}, wire[len(prefix):], at.Add(11*time.Second), false)
				require.Len(t, sshOutput(t, dispatcher, sink), len(got))
			}
		})
	}
}

func TestSSHCanonicalBannerBytesAreLosslesslyEscapedForWire(t *testing.T) {
	wire := sshInitialWires(t)[0]
	bannerEnd := bytes.IndexByte(wire, '\n') + 1
	banner := "SSH-2.0-fixture comment\xff\x1b[31m"
	payload := append([]byte(banner+"\r\n"), wire[bannerEnd:]...)
	runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
	source := Source{NodeID: "hunter", CaptureSource: "capture"}
	sshHandshake(t, runtime, source, eventfixture.BaseTime, true)
	observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1001, ACK: true}, payload, eventfixture.BaseTime.Add(time.Millisecond), true)
	got := sshOutput(t, dispatcher, sink)
	require.Len(t, got, 2)
	for _, event := range got {
		require.True(t, event.BannerEscaped)
		raw, err := strconv.Unquote(event.Banner)
		require.NoError(t, err)
		require.Equal(t, banner, raw)
	}
	require.Equal(t, events.SSHStatusComplete, got[1].Status)
	require.NotEmpty(t, got[1].HASSH)
}

func TestSSHCanonicalStateAdmissionIsGloballyBoundedAndOptOutWorks(t *testing.T) {
	for _, limit := range []string{"flows", "bytes", "disabled", "unrelated"} {
		t.Run(limit, func(t *testing.T) {
			policy := eventconfig.DefaultSSH()
			policy.MaxFlows = 1
			if limit == "bytes" {
				policy.MaxFlows = 10
				policy.MaxBytes = sshFlowReservationBytes
			}
			if limit == "disabled" {
				policy.Enabled = false
			}
			runtime, dispatcher, sink := sshRuntime(t, policy)
			for i := range 3 {
				source := Source{NodeID: fmt.Sprintf("hunter-%d", i), CaptureEpoch: "capture"}
				payload := []byte("SSH-2.0-fixture\r\n")
				if limit == "unrelated" {
					payload = []byte("arbitrary bytes on an SSH port\r\n")
				}
				sshHandshake(t, runtime, source, eventfixture.BaseTime, false)
				observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1001, ACK: true}, payload, eventfixture.BaseTime.Add(time.Millisecond), false)
			}
			stats := runtime.Stats().SSH
			if limit == "disabled" || limit == "unrelated" {
				require.Zero(t, stats.Admitted)
				require.Zero(t, stats.ReservedBytes)
				require.Empty(t, sshOutput(t, dispatcher, sink))
			} else {
				require.Equal(t, uint64(1), stats.Admitted)
				require.Equal(t, uint64(2), stats.Rejected)
				require.Equal(t, 1, stats.ActiveFlows)
				require.Equal(t, sshFlowReservationBytes, stats.ReservedBytes)
			}
			runtime.EOF()
			require.Zero(t, runtime.Stats().SSH.ActiveFlows)
			require.Zero(t, runtime.Stats().SSH.ReservedBytes)
		})
	}
}

func TestSSHCanonicalHTTPBodyCannotClaimHandshake(t *testing.T) {
	wire := sshInitialWires(t)[0]
	headers := []byte(fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n\r\n", len(wire)))
	message := append(append([]byte(nil), headers...), wire...)
	for _, transported := range []bool{false, true} {
		for _, framing := range []string{"coalesced", "headers-then-body", "split-start-line-and-body"} {
			t.Run(fmt.Sprintf("transported=%t/%s", transported, framing), func(t *testing.T) {
				runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
				source := Source{NodeID: "http", CaptureEpoch: "http-body"}
				var parts [][]byte
				switch framing {
				case "coalesced":
					parts = [][]byte{message}
				case "headers-then-body":
					parts = [][]byte{headers, wire}
				case "split-start-line-and-body":
					parts = [][]byte{headers[:3], headers[3:], wire[:4], wire[4:]}
				}
				sequence := uint32(1001)
				for i, payload := range parts {
					// ObserveCaptured supplies an SSH packet hint even on the
					// body fragments. It cannot replace validated HTTP framing.
					observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: sequence, ACK: true, DstPort: 80}, payload, eventfixture.BaseTime.Add(time.Duration(i)*time.Millisecond), transported)
					sequence += uint32(len(payload))
				}
				runtime.EOF()
				require.Empty(t, sshOutput(t, dispatcher, sink), "body bytes belong to their positively framed HTTP message")
				require.Zero(t, runtime.Stats().SSH.Admitted)
				sink.mu.Lock()
				var requests []events.HTTPEvent
				for _, event := range sink.events {
					if request, ok := event.(events.HTTPEvent); ok {
						requests = append(requests, request)
					}
				}
				sink.mu.Unlock()
				require.Len(t, requests, 1, "the complete original HTTP observation is retained")
				require.Equal(t, "POST", requests[0].Method)
				require.Equal(t, "/upload", requests[0].URI)
				require.Equal(t, "example.test", requests[0].Host)
				require.EqualValues(t, len(wire), requests[0].RequestBodyLength)
			})
		}
	}
}

func TestSSHCanonicalHTTPFrameOwnershipEndsBeforeTLS(t *testing.T) {
	runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
	source := Source{NodeID: "http", CaptureEpoch: "upgrade"}
	header := []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1001, ACK: true, DstPort: 80}, header, eventfixture.BaseTime, false)
	observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1001 + uint32(len(header)), ACK: true, DstPort: 80}, testClientHello(), eventfixture.BaseTime.Add(time.Millisecond), false)
	runtime.EOF()
	require.Empty(t, sshOutput(t, dispatcher, sink))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	httpCount, tlsCount := 0, 0
	for _, event := range sink.events {
		switch event.(type) {
		case events.HTTPEvent:
			httpCount++
		case events.TLSEvent:
			tlsCount++
		}
	}
	require.Equal(t, 1, httpCount)
	require.Equal(t, 1, tlsCount, "a complete HTTP message must release ownership for a later TLS handshake")
}

func TestSSHCanonicalHTTPPortAndServerPreludeRemainEligible(t *testing.T) {
	wires := sshInitialWires(t)
	for _, port := range []layers.TCPPort{80, eventfixture.SSHServerPort} {
		t.Run(strconv.Itoa(int(port)), func(t *testing.T) {
			runtime, dispatcher, sink := sshRuntime(t, eventconfig.DefaultSSH())
			source := Source{NodeID: "ssh", CaptureEpoch: "server-prelude"}
			at := eventfixture.BaseTime
			observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1000, SYN: true, DstPort: port}, nil, at, false)
			observeSSHSegment(t, runtime, source, false, layers.TCP{Seq: 9000, SYN: true, ACK: true, Ack: 1001, SrcPort: port}, nil, at.Add(time.Millisecond), false)
			prelude := []byte("maintenance notice before server identification\r\n")
			first := append(append([]byte(nil), prelude...), wires[1][:2]...)
			observeSSHSegment(t, runtime, source, false, layers.TCP{Seq: 9001, ACK: true, SrcPort: port}, first, at.Add(2*time.Millisecond), false)
			observeSSHSegment(t, runtime, source, false, layers.TCP{Seq: uint32(9001 + len(first)), ACK: true, SrcPort: port}, wires[1][2:], at.Add(3*time.Millisecond), false)
			observeSSHSegment(t, runtime, source, true, layers.TCP{Seq: 1001, ACK: true, DstPort: port}, wires[0], at.Add(4*time.Millisecond), false)
			runtime.EOF()
			got := sshOutput(t, dispatcher, sink)
			require.Len(t, got, 4, "port alone must not reserve an application, and supported SSH preludes remain valid")
			complete := 0
			for _, event := range got {
				if event.Status == events.SSHStatusComplete {
					complete++
					require.NotEmpty(t, event.HASSH)
				}
			}
			require.Equal(t, 2, complete)
		})
	}
}
