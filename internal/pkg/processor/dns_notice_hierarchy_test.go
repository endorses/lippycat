//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func dnsNoticeChildCapabilities() *management.EventForwardingCapabilities {
	caps := eventForwardingCapabilities(protoadapter.SupportedKindIDs(true)...)
	caps.StatefulAnalysisFeatures = append(caps.StatefulAnalysisFeatures, protoadapter.InventoryProductionFeature, protoadapter.DNSNoticeProductionFeature)
	return caps
}

func TestDNSNoticeRawForwardingHopRejectsEventOnlyChildren(t *testing.T) {
	pki := newRelayTestPKI(t)
	terminal := startDNSNoticeIntegrationNode(t, pki, Config{ProcessorID: "notice-terminal", RelayOrigins: map[string][]string{"notice-middle": {"notice-child"}}}, nil)
	middle := startDNSNoticeIntegrationNode(t, pki, Config{ProcessorID: "notice-middle", UpstreamAddr: terminal.address, UpstreamForwardMode: "packets"}, nil)
	require.Eventually(t, middle.processor.upstreamManager.IsConnected, 5*time.Second, time.Millisecond)
	require.False(t, middle.processor.monitorEventMode())
	pair, _, _ := pki.identity(t, "notice-child")
	conn, err := grpc.NewClient(middle.address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool})))
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()
	client := management.NewManagementServiceClient(conn)
	for _, processorChild := range []bool{false, true} {
		for _, allowFallback := range []bool{false, true} {
			caps := dnsNoticeChildCapabilities()
			caps.AllowPacketFallback = allowFallback
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if processorChild {
				response, err := client.RegisterProcessor(ctx, &management.ProcessorRegistration{ProcessorId: "notice-child", ListenAddress: "127.0.0.1:1", EventForwarding: caps})
				if allowFallback {
					require.NoError(t, err)
					require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, response.AcceptedForwardingMode)
					require.Contains(t, response.ForwardingNotice, "cannot relay event-only")
				} else {
					require.Equal(t, codes.FailedPrecondition, status.Code(err))
					require.Contains(t, err.Error(), "cannot relay event-only")
				}
			} else {
				response, err := client.RegisterHunter(ctx, &management.HunterRegistration{HunterId: "notice-child", EventForwarding: caps})
				if allowFallback {
					require.NoError(t, err)
					require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, response.AcceptedForwardingMode)
					require.Contains(t, response.ForwardingNotice, "cannot relay event-only")
				} else {
					require.Equal(t, codes.FailedPrecondition, status.Code(err))
					require.Contains(t, err.Error(), "cannot relay event-only")
				}
			}
			cancel()
		}
	}
	// Initial fallback leaves the requested config unchanged while the manager
	// owns effective PACKETS. Exercise that distinction without mutating a live
	// processor's configuration concurrently with its workers.
	fallback := &Processor{config: Config{UpstreamAddr: terminal.address, UpstreamForwardMode: "events", EventAnalysis: dnsNoticeIntegrationPolicy()}, upstreamManager: middle.processor.upstreamManager}
	caps := dnsNoticeChildCapabilities()
	_, _, _, _, _, err = fallback.negotiateEventForwarding(caps)
	require.ErrorContains(t, err, "cannot relay event-only")
	caps.AllowPacketFallback = true
	mode, _, _, _, reason, err := fallback.negotiateEventForwarding(caps)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, mode)
	require.Contains(t, reason, "explicit packet fallback")
}
