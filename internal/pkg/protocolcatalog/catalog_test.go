package protocolcatalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalog(t *testing.T) {
	t.Parallel()

	want := map[string][]string{
		"dns":   {"bpf", "ip_address", "dns_domain"},
		"email": {"bpf", "ip_address", "email_address", "email_subject"},
		"http":  {"bpf", "ip_address", "http_host", "http_path"},
		"tls":   {"bpf", "ip_address", "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4"},
		"voip":  nil,
	}
	for name, filterTypes := range want {
		spec, ok := Lookup(name)
		require.True(t, ok, name)
		assert.Equal(t, name, spec.Name)
		assert.Equal(t, filterTypes, spec.SupportedFilterTypes)
	}
}

func TestLookupReturnsIndependentFilterTypes(t *testing.T) {
	t.Parallel()

	first := MustLookup("dns")
	first.SupportedFilterTypes[0] = "changed"
	second := MustLookup("dns")
	assert.Equal(t, "bpf", second.SupportedFilterTypes[0])
}
