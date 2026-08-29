// Package protocolcatalog defines protocol identity and filter capabilities
// shared by command composition roots.
package protocolcatalog

// Spec is the protocol-neutral part of a command's runtime specification.
// Mode-specific callbacks and configuration remain in the command packages.
type Spec struct {
	Name                 string
	SupportedFilterTypes []string
}

var specs = map[string]Spec{
	"dns": {
		Name:                 "dns",
		SupportedFilterTypes: []string{"bpf", "ip_address", "dns_domain"},
	},
	"email": {
		Name:                 "email",
		SupportedFilterTypes: []string{"bpf", "ip_address", "email_address", "email_subject"},
	},
	"http": {
		Name:                 "http",
		SupportedFilterTypes: []string{"bpf", "ip_address", "http_host", "http_path"},
	},
	"tls": {
		Name:                 "tls",
		SupportedFilterTypes: []string{"bpf", "ip_address", "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4"},
	},
	"voip": {
		Name: "voip",
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
