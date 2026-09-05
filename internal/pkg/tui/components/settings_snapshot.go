//go:build tui || all

package components

import "github.com/endorses/lippycat/internal/pkg/tui/components/settings"

// InstallCaptureConfiguration restores the installed capture configuration.
// An uncommitted replacement must not become the settings for a ready dataset.
func (s *SettingsView) InstallCaptureConfiguration(msg RestartCaptureMsg) {
	s.modeType = msg.Mode
	if msg.Mode == CaptureModeOffline {
		s.currentMode = settings.NewOfflineSettingsFiles(msg.PCAPFiles, msg.BufferSize, msg.Filter, s.theme)
	} else {
		s.currentMode = s.factory.CreateMode(msg.Mode, msg.BufferSize, msg.Filter, msg.Interface, msg.Promiscuous, "", msg.NodesFile)
	}
	s.currentMode.SetSize(s.width, s.height)
	s.errorMessage = ""
}
