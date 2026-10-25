package eventconfig

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/spf13/viper"
)

// DNSPolicy controls canonical DNS observations and opt-in security notices.
// Detector bounds apply globally across capture scopes in one analysis runtime.
type DNSPolicy struct {
	Ports           []uint16
	DetectTunneling bool
	Threshold       float64
	Debounce        time.Duration
	Detector        dns.TunnelingConfig
}

func DefaultDNS() DNSPolicy {
	detector := dns.DefaultTunnelingConfig()
	detector.DisableJanitor = true
	detector.MaxTrackedSubdomains = 100
	return DNSPolicy{Ports: []uint16{53, 5353}, Threshold: 0.7, Debounce: 5 * time.Minute, Detector: detector}
}

// EffectiveDNS preserves compatibility with older embedded Config literals.
func (c Config) EffectiveDNS() DNSPolicy {
	d := DefaultDNS()
	if c.DNS != nil {
		d = *c.DNS
	}
	d.Ports = append([]uint16(nil), d.Ports...)
	d.Detector.SuspiciousRecordTypes = append([]string(nil), d.Detector.SuspiciousRecordTypes...)
	return d
}

func (d DNSPolicy) Validate() error {
	if len(d.Ports) == 0 {
		return fmt.Errorf("DNS ports must not be empty")
	}
	for _, p := range d.Ports {
		if p == 0 {
			return fmt.Errorf("DNS port must be nonzero")
		}
	}
	if math.IsNaN(d.Threshold) || math.IsInf(d.Threshold, 0) || d.Threshold < 0 || d.Threshold > 1 {
		return fmt.Errorf("DNS tunneling threshold must be finite and in [0,1]")
	}
	if d.Debounce < 0 {
		return fmt.Errorf("DNS tunneling debounce must not be negative")
	}
	c := d.Detector
	if math.IsNaN(c.EntropyThreshold) || math.IsInf(c.EntropyThreshold, 0) || c.EntropyThreshold < 0 {
		return fmt.Errorf("DNS entropy threshold must be finite and nonnegative")
	}
	if c.MinSubdomainLength <= 0 || c.MaxUniqueSubdomains <= 0 || c.MaxDomains <= 0 || c.MaxAge <= 0 || c.MaxTrackedSubdomains <= 0 || c.MaxSourceIPs <= 0 {
		return fmt.Errorf("DNS detector limits and retention must be positive")
	}
	// Notice transport has a fixed collection ceiling; local evidence must fit.
	if c.MaxSourceIPs > 4096 {
		return fmt.Errorf("DNS source evidence limit exceeds transport ceiling 4096")
	}
	if !c.DisableJanitor {
		return fmt.Errorf("canonical DNS detector must use the observation clock")
	}
	return nil
}

func readDNS(v *viper.Viper) *DNSPolicy {
	d := DefaultDNS()
	if v.IsSet("dns.detect_tunneling") {
		d.DetectTunneling = v.GetBool("dns.detect_tunneling")
	}
	if v.IsSet("events.dns.notices") {
		d.DetectTunneling = v.GetBool("events.dns.notices")
	}
	// Existing command options remain aliases for the canonical decision policy.
	if v.GetString("processor.tunneling_command") != "" && !v.IsSet("dns.detect_tunneling") && !v.IsSet("events.dns.notices") {
		d.DetectTunneling = true
	}
	for _, key := range []string{"processor.tunneling_threshold", "events.dns.threshold"} {
		if v.IsSet(key) {
			d.Threshold = v.GetFloat64(key)
		}
	}
	for _, key := range []string{"processor.tunneling_debounce", "events.dns.debounce"} {
		if v.IsSet(key) {
			d.Debounce = v.GetDuration(key)
		}
	}
	for _, key := range []string{"dns.ports", "hunter.dns.ports", "tap.dns.ports", "events.dns.ports"} {
		if !v.IsSet(key) {
			continue
		}
		d.Ports = nil
		for _, item := range v.GetStringSlice(key) {
			for _, part := range strings.Split(item, ",") {
				p, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
				if err != nil {
					d.Ports = append(d.Ports, 0)
				} else {
					d.Ports = append(d.Ports, uint16(p))
				}
			}
		}
	}
	for key, dst := range map[string]*int{"max_domains": &d.Detector.MaxDomains, "max_subdomains": &d.Detector.MaxTrackedSubdomains, "max_source_ips": &d.Detector.MaxSourceIPs} {
		if v.IsSet("events.dns." + key) {
			*dst = v.GetInt("events.dns." + key)
		}
	}
	if v.IsSet("events.dns.retention") {
		d.Detector.MaxAge = v.GetDuration("events.dns.retention")
	}
	return &d
}

func (d *DNSPolicy) canonicalize() {
	sort.Slice(d.Ports, func(i, j int) bool { return d.Ports[i] < d.Ports[j] })
	ports := d.Ports[:0]
	for _, port := range d.Ports {
		if len(ports) == 0 || ports[len(ports)-1] != port {
			ports = append(ports, port)
		}
	}
	d.Ports = ports
	sort.Strings(d.Detector.SuspiciousRecordTypes)
}
