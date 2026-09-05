//go:build tui || all

package tui

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tls/decrypt"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestOfflineModeSwitchReleasesDecryptedDetails(t *testing.T) {
	for _, mode := range []components.CaptureMode{components.CaptureModeLive, components.CaptureModeRemote} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			m, open := offlineLifecycleModel(t)
			m, cmd := m.openOffline(open)
			result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
			require.NoError(t, result.err)
			d, err := NewTLSDecryptor("")
			require.NoError(t, err)
			result.session.TLSDecryptor = d
			src, dst := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
			key := decrypt.FlowKey(src, dst, 12345, 443)
			fragment := make([]byte, 39)
			fragment[0] = 1
			require.NoError(t, d.sessionManager.ProcessClientHello(key, src, dst, 12345, 443, &decrypt.Record{ContentType: 22, Fragment: fragment}))
			d.sessionManager.GetSession(key).ClientAppData = []byte("offline-secret-marker")
			global, err := NewTLSDecryptor("")
			require.NoError(t, err)
			require.NoError(t, global.sessionManager.ProcessClientHello(key, src, dst, 12345, 443, &decrypt.Record{ContentType: 22, Fragment: fragment}))
			global.sessionManager.GetSession(key).ClientAppData = []byte("current-live-marker")
			previousGlobal := GetTLSDecryptor()
			previousEnabled := viper.Get("watch.tls_decryption_enabled")
			SetTLSDecryptor(global)
			viper.Set("watch.tls_decryption_enabled", true)
			t.Cleanup(func() {
				SetTLSDecryptor(previousGlobal)
				viper.Set("watch.tls_decryption_enabled", previousEnabled)
				global.Stop()
			})
			m, cleanup := m.completeOffline(result)
			cleanup()
			packet := components.PacketDisplay{Timestamp: time.Now(), Protocol: "TLS", SrcIP: src.String(), DstIP: dst.String(), SrcPort: "12345", DstPort: "443"}
			m.uiState.DetailsPanel.SetSize(100, 100)
			m.uiState.DetailsPanel.SetPacket(&packet)
			require.Contains(t, m.uiState.DetailsPanel.View(false), "offline-secret-marker")
			require.NotContains(t, m.uiState.DetailsPanel.View(false), "current-live-marker")
			m, cmd = m.handleRestartCaptureMsg(components.RestartCaptureMsg{Mode: mode, BufferSize: 8})
			updated, _ := m.update(cmd())
			m = updated.(Model)
			require.NotContains(t, m.uiState.DetailsPanel.View(false), "offline-secret-marker")
			packet.Timestamp = packet.Timestamp.Add(time.Second)
			m.uiState.DetailsPanel.SetPacket(&packet)
			require.NotContains(t, m.uiState.DetailsPanel.View(false), "offline-secret-marker")
			require.Contains(t, m.uiState.DetailsPanel.View(false), "current-live-marker")
		})
	}
}
