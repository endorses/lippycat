//go:build hunter || all

package hunt

import (
	"context"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestHuntCapturePoliciesConfig(t *testing.T) {
	previousSignalling, previousMedia := viper.Get("hunter.voip.signalling_policy"), viper.Get("hunter.voip.media_policy")
	t.Cleanup(func() {
		viper.Set("hunter.voip.signalling_policy", previousSignalling)
		viper.Set("hunter.voip.media_policy", previousMedia)
	})
	for _, tt := range []struct {
		signalling, media string
		want              voip.CapturePolicies
		invalid           bool
	}{
		{want: voip.CapturePolicies{Signalling: voip.SignallingMatched, Media: voip.MediaLocal}},
		{signalling: "all", media: "processor", want: voip.CapturePolicies{Signalling: voip.SignallingAll, Media: voip.MediaProcessor}},
		{signalling: "none", media: "local", want: voip.CapturePolicies{Signalling: voip.SignallingNone, Media: voip.MediaLocal}},
		{signalling: "everything", media: "local", invalid: true},
		{signalling: "all", media: "automatic", invalid: true},
	} {
		t.Run(tt.signalling+"/"+tt.media, func(t *testing.T) {
			viper.Set("hunter.voip.signalling_policy", tt.signalling)
			viper.Set("hunter.voip.media_policy", tt.media)
			actual, err := huntCapturePolicies()
			if tt.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, actual)
			config := buildHunterConfig(protocolHunterConfigSpec("voip", ""))
			require.Equal(t, tt.signalling, config.VoIPSignallingPolicy)
			require.Equal(t, tt.media, config.VoIPMediaPolicy)
		})
	}
}

func TestHuntCapturePolicyFlags(t *testing.T) {
	for _, tt := range []struct{ name, key, defaultValue string }{
		{"signalling-policy", "hunter.voip.signalling_policy", "matched"},
		{"media-policy", "hunter.voip.media_policy", "local"},
	} {
		flag := voipHuntCmd.Flags().Lookup(tt.name)
		require.NotNil(t, flag)
		require.Equal(t, tt.defaultValue, flag.DefValue)
	}
}

func TestAdmissionHunterProcessorPoliciesDoNotSelectLocalMedia(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"second": 1}
	backend := &hunterAdmissionMap{entries: make(map[mediaadmission.EndpointKey]struct{})}
	controller, err := mediaadmission.NewController(t.Context(), cfg, backend)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, controller.Close(context.Background())) })
	metadata, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	session := &admissionintegration.Session{Config: cfg, Controller: controller, Metadata: metadata}
	router, err := newAdmissionHunterRouter(t.Context(), admissionForwarder{}, session, []string{"first", "second"}, *voip.DefaultConfig())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close()) })
	require.NoError(t, router.SetCapturePolicies(voip.CapturePolicies{Signalling: voip.SignallingAll, Media: voip.MediaProcessor}, nil))
	router.SetApplicationFilter(&admissionMatch{selected: true})
	sdp := "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 45000 RTP/AVP 0\r\n"
	for _, iface := range []string{"first", "second"} {
		router.ProcessPacket(admissionUDPPacket(t, iface, admissionMessage(sdp)))
	}
	nf := gopacket.NewFlow(layers.EndpointIPv4, net.ParseIP("192.0.2.1").To4(), net.ParseIP("192.0.2.2").To4())
	tf := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x13, 0xc4}, []byte{0x13, 0xc4})
	for _, scope := range router.domains {
		require.True(t, scope.tcp.HandleSIPMessageAt(admissionMessage(sdp), "shared-id", "192.0.2.1:5060", "192.0.2.2:5060", nf, tf, time.Now()))
		require.False(t, scope.buffer.IsCallMatched("shared-id"))
		require.Empty(t, scope.tracker.AdmissionRegistry().ActiveCalls())
	}
	require.Empty(t, backend.entries, "SIP export and local matches cannot create independent media admission in processor mode")
}
