package cmdutil

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RegisterMediaAdmissionFlags is called only by hunt/tap VoIP. Mode and failure
// policy never enable admission by themselves. YAML resource defaults are set
// here so UnmarshalKey observes the same precedence as bound CLI flags.
func RegisterMediaAdmissionFlags(cmd *cobra.Command, v *viper.Viper, prefix string) {
	defaults := mediaadmission.DefaultConfig()
	cmd.Flags().Bool("rtp-ebpf", false, "Enable Linux eBPF admission for media belonging to selected VoIP calls")
	cmd.Flags().String("rtp-ebpf-mode", string(defaults.Mode), "RTP eBPF admission mode: enforce or shadow (requires --rtp-ebpf)")
	cmd.Flags().String("rtp-ebpf-failure-policy", string(defaults.FailurePolicy), "RTP eBPF runtime update failure policy: open or closed")
	cmd.Flags().Uint32("rtp-ebpf-shadow-sample-every", defaults.ShadowSampleEvery, "Sample approximately one in N shadow frame identities with shared kernel/userspace eligibility")
	for flag, key := range map[string]string{"rtp-ebpf": "enabled", "rtp-ebpf-mode": "mode", "rtp-ebpf-failure-policy": "failure_policy", "rtp-ebpf-shadow-sample-every": "shadow_sample_every"} {
		if err := v.BindPFlag(prefix+"."+key, cmd.Flags().Lookup(flag)); err != nil {
			panic(fmt.Errorf("bind RTP eBPF flag: %w", err))
		}
	}
	for key, value := range map[string]any{
		"endpoint_capacity":         defaults.EndpointCapacity,
		"owner_capacity":            defaults.OwnerCapacity,
		"max_endpoints_per_owner":   defaults.MaxEndpointsPerOwner,
		"pending_dialog_capacity":   defaults.PendingDialogCapacity,
		"pending_endpoint_capacity": defaults.PendingEndpointCapacity,
		"pending_bytes":             defaults.PendingBytes,
		"pending_ttl":               defaults.PendingTTL,
		"replay_window":             defaults.ReplayWindow,
		"replay_guard_capacity":     defaults.ReplayGuardCapacity,
		"replay_guard_bytes":        defaults.ReplayGuardBytes,
		"expiration_batch":          defaults.ExpirationBatch,
		"retry_interval":            defaults.RetryInterval,
		"shadow_evidence_capacity":  defaults.ShadowEvidenceCapacity,
		"missing_media_interval":    defaults.MissingMediaInterval,
	} {
		v.SetDefault(prefix+"."+key, value)
	}
}

func ReadMediaAdmissionConfig(v *viper.Viper, prefix string) (mediaadmission.Config, error) {
	config := mediaadmission.DefaultConfig()
	// Resolve each leaf through Viper: UnmarshalKey on a parent does not include
	// changed flags bound to nested keys.
	settings := viper.New()
	for _, key := range v.AllKeys() {
		if child, ok := strings.CutPrefix(key, prefix+"."); ok {
			settings.Set(child, v.Get(key))
		}
	}
	if err := settings.Unmarshal(&config); err != nil {
		return config, fmt.Errorf("decode %s: %w", prefix, err)
	}
	if err := config.Validate(); err != nil {
		return config, fmt.Errorf("%s: %w", prefix, err)
	}
	return config, nil
}
