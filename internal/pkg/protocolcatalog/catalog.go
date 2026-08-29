// Package protocolcatalog defines protocol identity and filter capabilities
// shared by command composition roots.
package protocolcatalog

// Spec is the protocol-neutral part of a command's runtime specification.
// Mode-specific callbacks and configuration remain in the command packages.
type Spec struct {
	Name                 string
	Analyzer             AnalyzerKind
	SupportedFilterTypes []string
	Hunter               HunterSpec
}

// AnalyzerKind is the stable analyzer identity consumed by topology adapters.
// It deliberately lives in the declarative catalog so command packages do not
// maintain parallel protocol-to-analyzer registries.
type AnalyzerKind string

const (
	AnalyzerGeneric AnalyzerKind = "generic"
	AnalyzerDNS     AnalyzerKind = "dns"
	AnalyzerEmail   AnalyzerKind = "email"
	AnalyzerHTTP    AnalyzerKind = "http"
	AnalyzerTLS     AnalyzerKind = "tls"
	AnalyzerVoIP    AnalyzerKind = "voip"
)

// HunterSpec declares the protocol's topology policy when it runs at the edge.
// Transport values and flag-derived values remain owned by cmd/hunt; these
// stable protocol capabilities belong here so every hunter composition consumes
// the same registration.
type HunterSpec struct {
	VoIPMode            bool
	EnableVoIPFilter    bool
	UseGPUConfig        bool
	IncludeDiskBuffer   bool
	IncludeFilterPolicy bool
}

var specs = map[string]Spec{
	"generic": {
		Name:     "generic",
		Analyzer: AnalyzerGeneric,
		Hunter: HunterSpec{
			UseGPUConfig:        true,
			IncludeDiskBuffer:   true,
			IncludeFilterPolicy: true,
		},
	},
	"dns": {
		Name:                 "dns",
		Analyzer:             AnalyzerDNS,
		SupportedFilterTypes: []string{"bpf", "ip_address", "dns_domain"},
	},
	"email": {
		Name:                 "email",
		Analyzer:             AnalyzerEmail,
		SupportedFilterTypes: []string{"bpf", "ip_address", "email_address", "email_subject"},
	},
	"http": {
		Name:                 "http",
		Analyzer:             AnalyzerHTTP,
		SupportedFilterTypes: []string{"bpf", "ip_address", "http_host", "http_path"},
	},
	"tls": {
		Name:                 "tls",
		Analyzer:             AnalyzerTLS,
		SupportedFilterTypes: []string{"bpf", "ip_address", "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4"},
	},
	"voip": {
		Name:     "voip",
		Analyzer: AnalyzerVoIP,
		Hunter: HunterSpec{
			VoIPMode:            true,
			EnableVoIPFilter:    true,
			UseGPUConfig:        true,
			IncludeFilterPolicy: true,
		},
	},
}

// Lookup returns a copy of a registered protocol specification.
func Lookup(name string) (Spec, bool) {
	spec, ok := specs[name]
	if !ok {
		return Spec{}, false
	}
	spec.SupportedFilterTypes = append([]string(nil), spec.SupportedFilterTypes...)
	return spec, true
}

// MustLookup returns a copy of a registered protocol specification and panics
// for programmer errors in command composition.
func MustLookup(name string) Spec {
	spec, ok := Lookup(name)
	if !ok {
		panic("unknown protocol: " + name)
	}
	return spec
}
