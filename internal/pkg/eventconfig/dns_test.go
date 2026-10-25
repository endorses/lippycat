package eventconfig

import (
	"math"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestDNSNoticePolicyAliasesAndExplicitDisable(t *testing.T) {
	v := viper.New()
	require.False(t, FromViper(v).EffectiveDNS().DetectTunneling)
	v.Set("dns.detect_tunneling", true)
	v.Set("processor.tunneling_threshold", 0.4)
	v.Set("processor.tunneling_debounce", "3s")
	v.Set("tap.dns.ports", "1053,2053")
	d := FromViper(v).EffectiveDNS()
	require.True(t, d.DetectTunneling)
	require.Equal(t, 0.4, d.Threshold)
	require.Equal(t, 3*time.Second, d.Debounce)
	require.Equal(t, []uint16{1053, 2053}, d.Ports)
	v.Set("events.dns.notices", false)
	v.Set("events.dns.threshold", 0.6)
	d = FromViper(v).EffectiveDNS()
	require.False(t, d.DetectTunneling)
	require.Equal(t, 0.6, d.Threshold)
	v = viper.New()
	v.Set("processor.tunneling_command", "echo %domain%")
	require.True(t, FromViper(v).EffectiveDNS().DetectTunneling)
	v.Set("dns.detect_tunneling", false)
	require.False(t, FromViper(v).EffectiveDNS().DetectTunneling)
}

func TestDNSNoticePolicyBoundsAndFingerprint(t *testing.T) {
	a := Default()
	b := a.Clone()
	b.DNS.Ports = []uint16{5353, 53, 53}
	require.Equal(t, a.Fingerprint(), b.Fingerprint())
	b.DNS.DetectTunneling = true
	require.NotEqual(t, a.Fingerprint(), b.Fingerprint())
	require.False(t, a.EffectiveDNS().DetectTunneling)
	b.DNS.Detector.SuspiciousRecordTypes[0] = "A"
	require.Equal(t, "TXT", a.EffectiveDNS().Detector.SuspiciousRecordTypes[0])
	for key, value := range map[string]any{"events.dns.max_domains": 0, "events.dns.max_subdomains": -1, "events.dns.max_source_ips": 4097, "events.dns.retention": "0s", "events.dns.threshold": math.NaN(), "events.dns.debounce": "-1s", "events.dns.ports": "bad"} {
		t.Run(key, func(t *testing.T) { v := viper.New(); v.Set(key, value); require.Error(t, FromViper(v).Validate()) })
	}
}

func TestDNSNoticeFlagDefaultsDoNotMaskLegacyPolicy(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	flags := pflag.NewFlagSet("dns", pflag.ContinueOnError)
	Register(flags)
	viper.Set("dns.detect_tunneling", true)
	viper.Set("processor.tunneling_threshold", 0.3)
	viper.Set("dns.ports", "1053")
	d := FromViper(viper.GetViper()).EffectiveDNS()
	require.True(t, d.DetectTunneling)
	require.Equal(t, 0.3, d.Threshold)
	require.Equal(t, []uint16{1053}, d.Ports)
	require.NoError(t, flags.Parse([]string{"--dns-notices=false", "--dns-notice-threshold=0.5", "--dns-analysis-ports=5353"}))
	d = FromViper(viper.GetViper()).EffectiveDNS()
	require.False(t, d.DetectTunneling)
	require.Equal(t, 0.5, d.Threshold)
	require.Equal(t, []uint16{5353}, d.Ports)
}
