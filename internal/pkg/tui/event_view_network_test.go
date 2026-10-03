//go:build tui || all

package tui

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestNetworkEventScopes(t *testing.T) {
	env := testEventEnvelope("network", 1)
	dhcp, ntp := events.NewDHCPEvent(env), events.NewNTPEvent(env)
	host, service := events.NewKnownHostEvent(env), events.NewKnownServiceEvent(env)
	for _, event := range []events.Event{dhcp, ntp, host, service} {
		require.True(t, eventMatchesProtocol(event, "All"))
	}
	for _, scope := range []string{"DHCP", "NTP", "UDP"} {
		require.True(t, eventScopeAvailable(scope))
	}
	require.True(t, eventMatchesProtocol(dhcp, "DHCP"))
	require.True(t, eventMatchesProtocol(ntp, "NTP"))
	require.True(t, eventMatchesProtocol(dhcp, "UDP"))
	require.True(t, eventMatchesProtocol(ntp, "UDP"))
	require.False(t, eventMatchesProtocol(dhcp, "NTP"))
	require.False(t, eventMatchesProtocol(ntp, "DHCP"))
	for _, event := range []events.Event{dhcp, ntp, host, service} {
		require.False(t, eventMatchesProtocol(event, "TCP"))
		require.False(t, eventMatchesProtocol(event, "VoIP (SIP/RTP)"))
	}
}
