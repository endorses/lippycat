//go:build cli || all

package sniff

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestSniffDNSNoticeDemandAndLegacyScope(t *testing.T) {
	setSniffAnalysisConfig(t, map[string]any{"logs.dir": "", "logs.streams": []string{}, "files.extract": false, "dns.detect_tunneling": true, "events.dns.notices": false, "events.dns.threshold": 0.0})
	require.False(t, sniffAnalysisPolicy("sniff").EffectiveDNS().DetectTunneling)
	require.False(t, sniffAnalysisPolicy("dns").EffectiveDNS().DetectTunneling, "explicit shared disable wins legacy enablement")
	viper.Set("events.dns.notices", true)
	session, err := newSniffEventSession("", nil, "no-log-or-command", nil)
	require.NoError(t, err)
	require.NotNil(t, session, "enabled detection owns analysis without log or command hooks")
	defer func() { session.analysis.Close(); require.NoError(t, session.dispatcher.Close(context.Background())) }()
	packet := gopacket.NewPacket(dnsPacket(t), layers.LayerTypeEthernet, gopacket.Default)
	require.NoError(t, session.analysis.ObservePacket(eventanalysis.Source{NodeID: "local"}, capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet}))
	require.EqualValues(t, 1, session.analysis.Stats().DNSNotices)
}
