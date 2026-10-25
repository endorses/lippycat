//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type sshNegotiationNode struct {
	p    *Processor
	conn *grpc.ClientConn
}

func sshNegotiationPolicy(enabled bool) *eventconfig.Config {
	p := eventconfig.Default()
	p.Inventory.Enabled = false
	s := p.EffectiveSSH()
	s.Enabled = enabled
	p.SSH = &s
	return &p
}
func startSSHNegotiationNode(t *testing.T, pki relayTestPKI, cfg Config) sshNegotiationNode {
	t.Helper()
	pair, cert, key := pki.identity(t, cfg.ProcessorID)
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.TLSEnabled, cfg.TLSClientAuth = true, true
	cfg.TLSCAFile, cfg.TLSCertFile, cfg.TLSKeyFile = pki.caFile, cert, key
	cfg.GracefulShutdownTimeout = 100 * time.Millisecond
	if cfg.EventAnalysis == nil {
		cfg.EventAnalysis = sshNegotiationPolicy(true)
	}
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("SSH negotiation processor did not join")
		}
	})
	require.Eventually(t, func() bool { return p.ListenAddr() != "" }, 5*time.Second, time.Millisecond)
	conn, err := grpc.NewClient(p.ListenAddr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return sshNegotiationNode{p, conn}
}
func sshNegotiationCaps(withKind, production, fallback bool) *management.EventForwardingCapabilities {
	c := &management.EventForwardingCapabilities{RequestedMode: management.ForwardingMode_FORWARDING_MODE_EVENTS, EventApiMajors: []uint32{1}, SemanticProfileRevision: 1, StatefulAnalysisFeatures: []string{"tcp_reassembly", "connection_tracking", "file_metadata"}, AllowPacketFallback: fallback}
	for _, kind := range protoadapter.SupportedKindIDs(false) {
		if kind != 13 || withKind {
			c.EventKinds = append(c.EventKinds, kind)
		}
	}
	if production {
		c.StatefulAnalysisFeatures = append(c.StatefulAnalysisFeatures, protoadapter.SSHProductionFeature)
	}
	return c
}

func TestSSHRequiredTerminalRelayEnforcesEveryChildProducer(t *testing.T) {
	pki := newRelayTestPKI(t)
	terminal := startSSHNegotiationNode(t, pki, Config{ProcessorID: "ssh-terminal", RelayOrigins: map[string][]string{"ssh-middle": {"legacy-child"}}, EventIngressProfile: "memory_only", LogConfig: &StructuredLogConfig{Enabled: true, Directory: t.TempDir(), Format: "json", Streams: []string{"ssh"}}})
	middle := startSSHNegotiationNode(t, pki, Config{ProcessorID: "ssh-middle", UpstreamAddr: terminal.p.ListenAddr(), UpstreamForwardMode: "events", UpstreamEventDeliveryProfile: "memory_only", UpstreamEventSpoolDirectory: t.TempDir()})
	require.Nil(t, middle.p.config.LogConfig, "coverage requirement must propagate without a local ssh log")
	require.Eventually(t, middle.p.upstreamManager.IsConnected, 5*time.Second, time.Millisecond)
	for _, processorChild := range []bool{false, true} {
		for _, withKind := range []bool{false, true} {
			for _, fallback := range []bool{false, true} {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				caps := sshNegotiationCaps(withKind, false, fallback)
				if processorChild {
					response, err := management.NewManagementServiceClient(middle.conn).RegisterProcessor(ctx, &management.ProcessorRegistration{ProcessorId: "legacy-child", ListenAddress: "127.0.0.1:1", EventForwarding: caps})
					if fallback {
						require.NoError(t, err)
						require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, response.GetAcceptedForwardingMode())
						require.Contains(t, response.ForwardingNotice, "SSH")
					} else {
						require.Equal(t, codes.FailedPrecondition, status.Code(err))
						require.Contains(t, err.Error(), "SSH")
					}
				} else {
					response, err := management.NewManagementServiceClient(middle.conn).RegisterHunter(ctx, &management.HunterRegistration{HunterId: "legacy-child", EventForwarding: caps})
					if fallback {
						require.NoError(t, err)
						require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, response.GetAcceptedForwardingMode())
						require.Contains(t, response.ForwardingNotice, "SSH")
					} else {
						require.Equal(t, codes.FailedPrecondition, status.Code(err))
						require.Contains(t, err.Error(), "SSH")
					}
				}
				cancel()
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := management.NewManagementServiceClient(middle.conn).RegisterHunter(ctx, &management.HunterRegistration{HunterId: "producing-child", EventForwarding: sshNegotiationCaps(true, true, false)})
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, response.AcceptedForwardingMode)
	require.Contains(t, response.AcceptedEventKinds, int32(eventsv1.EventKind_EVENT_KIND_SSH))
}

func TestSSHDisabledLocalPolicyCannotFallbackForRequiredCoverage(t *testing.T) {
	pki := newRelayTestPKI(t)
	node := startSSHNegotiationNode(t, pki, Config{ProcessorID: "ssh-disabled", EventAnalysis: sshNegotiationPolicy(false), EventIngressProfile: "memory_only", LogConfig: &StructuredLogConfig{Enabled: true, Directory: t.TempDir(), Format: "json", Streams: []string{"ssh"}}})
	client := management.NewManagementServiceClient(node.conn)
	for _, caps := range []*management.EventForwardingCapabilities{nil, {RequestedMode: management.ForwardingMode_FORWARDING_MODE_PACKETS}, sshNegotiationCaps(true, false, true), sshNegotiationCaps(false, false, true)} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := client.RegisterHunter(ctx, &management.HunterRegistration{HunterId: "ssh-disabled-source", EventForwarding: caps})
		cancel()
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Contains(t, err.Error(), "SSH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.RegisterHunter(ctx, &management.HunterRegistration{HunterId: "ssh-real-producer", EventForwarding: sshNegotiationCaps(true, true, true)})
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, response.AcceptedForwardingMode, "forwarded observations do not require rescoring with local disabled SSH")
}
