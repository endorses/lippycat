package capture

import "github.com/endorses/lippycat/internal/pkg/mediaadmission"

func captureAdmissionStatus(options []CaptureOptions) mediaadmission.StatusProvider {
	provider, _ := captureFilterInstaller(options).(mediaadmission.StatusProvider)
	return provider
}

// Fixed-cardinality heartbeat summary. No endpoint, selector or call identity is logged.
func admissionHeartbeatFields(s *mediaadmission.Snapshot) []any {
	if s == nil {
		return nil
	}
	var installed, pending int
	var compatible, updates, controls, lost uint64
	states := make(map[mediaadmission.State]int)
	for _, scope := range s.Scopes {
		states[scope.State]++
		installed += scope.InstalledEndpoints
		pending += scope.PendingUpdates
		compatible += scope.Counters[6] + scope.Counters[7] + scope.Counters[8]
		updates += scope.UpdateErrors
		controls += scope.ControlErrors
		lost += scope.Counters[11]
	}
	return []any{"rtp_ebpf_enabled", s.Enabled, "rtp_ebpf_mode", s.ConfiguredMode, "rtp_ebpf_scopes", len(s.Scopes), "rtp_ebpf_states", states, "rtp_ebpf_installed", installed, "rtp_ebpf_pending", pending, "rtp_ebpf_compatibility_passes", compatible, "rtp_ebpf_update_errors", updates, "rtp_ebpf_control_errors", controls, "rtp_ebpf_evidence_lost", lost, "rtp_ebpf_missing_media", s.Media.SelectedAnsweredWithoutMedia}
}
