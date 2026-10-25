package eventfixture

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	gossh "golang.org/x/crypto/ssh"
)

const (
	SSHClientPort = 40022
	SSHServerPort = 2222 // Deliberately requires identification on a custom port.
)

type sshWrite struct {
	client bool
	data   []byte
}

type sshRecordingConn struct {
	net.Conn
	client bool
	mu     *sync.Mutex
	writes *[]sshWrite
}

func (c *sshRecordingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n != 0 {
		c.mu.Lock()
		*c.writes = append(*c.writes, sshWrite{client: c.client, data: append([]byte(nil), data[:n]...)})
		c.mu.Unlock()
	}
	return n, err
}

func closeSSHFixture(closer interface{ Close() error }) error {
	if closer == nil {
		return nil
	}
	err := closer.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func closeSSHTransport(connection gossh.Conn) error {
	closeErr := closeSSHFixture(connection)
	waitErr := connection.Wait()
	if errors.Is(waitErr, net.ErrClosed) || errors.Is(waitErr, io.EOF) {
		waitErr = nil
	}
	return errors.Join(closeErr, waitErr)
}

// SSHMessages records an actual controlled x/crypto/ssh client/server exchange
// on loopback, then wraps its bytes in generated Ethernet/IPv4/TCP capture
// frames. The fixture contains no third-party packet capture. Capture times,
// addresses, ports, sequence numbers and segmentation are stable; SSH's random
// cookies and ephemeral exchange bytes are intentionally generated afresh.
// Neither host key nor fixture credentials have any production use.
func SSHMessages() (packets []capture.PacketInfo, resultErr error) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	signer, err := gossh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return nil, fmt.Errorf("create controlled SSH host key: %w", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for controlled SSH fixture: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, closeSSHFixture(listener)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var writes []sshWrite
	serverDone := make(chan error, 1)
	algorithms := gossh.Config{KeyExchanges: []string{"curve25519-sha256"}, Ciphers: []string{"aes128-ctr"}, MACs: []string{"hmac-sha2-256"}}
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		deadline, _ := ctx.Deadline()
		if err = connection.SetDeadline(deadline); err != nil {
			serverDone <- errors.Join(err, closeSSHFixture(connection))
			return
		}
		config := &gossh.ServerConfig{Config: algorithms, NoClientAuth: true, ServerVersion: "SSH-2.0-lippycat_fixture_server"}
		config.AddHostKey(signer)
		server, _, _, err := gossh.NewServerConn(&sshRecordingConn{Conn: connection, mu: &mu, writes: &writes}, config)
		if err != nil {
			serverDone <- errors.Join(err, closeSSHFixture(connection))
			return
		}
		serverDone <- closeSSHTransport(server)
	}()
	dialer := net.Dialer{}
	clientRaw, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		// Closing the listener releases an Accept that never got a connection.
		return nil, errors.Join(err, closeSSHFixture(listener), <-serverDone)
	}
	deadline, _ := ctx.Deadline()
	if err = clientRaw.SetDeadline(deadline); err != nil {
		return nil, errors.Join(err, closeSSHFixture(clientRaw), <-serverDone)
	}
	client, _, _, clientErr := gossh.NewClientConn(&sshRecordingConn{Conn: clientRaw, client: true, mu: &mu, writes: &writes}, "fixture.invalid", &gossh.ClientConfig{
		Config: algorithms, User: "fixture", ClientVersion: "SSH-2.0-lippycat_fixture_client", HostKeyCallback: gossh.FixedHostKey(signer.PublicKey()),
	})
	if clientErr != nil {
		return nil, errors.Join(clientErr, closeSSHFixture(clientRaw), <-serverDone)
	}
	if err = errors.Join(closeSSHTransport(client), <-serverDone); err != nil {
		return nil, err
	}
	appendPacket := func(client bool, tcp layers.TCP, payload []byte) error {
		packet, err := SSHSegment(client, tcp, payload, BaseTime.Add(time.Duration(len(packets))*time.Millisecond))
		if err == nil {
			packets = append(packets, packet)
		}
		return err
	}
	if err = appendPacket(true, layers.TCP{Seq: 1000, SYN: true}, nil); err != nil {
		return nil, err
	}
	if err = appendPacket(false, layers.TCP{Seq: 9000, Ack: 1001, SYN: true, ACK: true}, nil); err != nil {
		return nil, err
	}
	if err = appendPacket(true, layers.TCP{Seq: 1001, Ack: 9001, ACK: true}, nil); err != nil {
		return nil, err
	}
	next := [2]uint32{1001, 9001}
	mu.Lock()
	defer mu.Unlock()
	for _, write := range writes {
		direction := 1
		if write.client {
			direction = 0
		}
		for data := write.data; len(data) != 0; {
			n := min(37, len(data))
			if err = appendPacket(write.client, layers.TCP{Seq: next[direction], Ack: next[1-direction], ACK: true}, data[:n]); err != nil {
				return nil, err
			}
			next[direction] += uint32(n)
			data = data[n:]
		}
	}
	for direction := range 2 {
		if err = appendPacket(direction == 0, layers.TCP{Seq: next[direction], Ack: next[1-direction], ACK: true, FIN: true}, nil); err != nil {
			return nil, err
		}
	}
	return packets, nil
}

// SSHSegment uses the fixture's fixed addresses and default ports while
// accepting explicit TCP controls, nonzero port overrides and payload. This
// supports retransmission/gap/tuple-reuse tests with checksum-correct decoding.
func SSHSegment(client bool, tcp layers.TCP, payload []byte, at time.Time) (capture.PacketInfo, error) {
	src, dst := net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 20)
	sport, dport := layers.TCPPort(SSHClientPort), layers.TCPPort(SSHServerPort)
	if !client {
		src, dst, sport, dport = dst, src, dport, sport
	}
	if tcp.SrcPort != 0 {
		sport = tcp.SrcPort
	}
	if tcp.DstPort != 0 {
		dport = tcp.DstPort
	}
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
	tcp.SrcPort, tcp.DstPort, tcp.Window = sport, dport, 65535
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return capture.PacketInfo{}, err
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, &tcp, gopacket.Payload(payload)); err != nil {
		return capture.PacketInfo{}, err
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	return capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "ssh-fixture0"}, nil
}
