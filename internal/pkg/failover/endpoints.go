package failover

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Endpoint inherits the caller's TLS credentials and verification policy. An
// optional server name selects the certificate identity for this address.
type Endpoint struct {
	Address       string `mapstructure:"address"`
	TLSServerName string `mapstructure:"tls_server_name"`
}

// NormalizeEndpoints adapts the legacy scalar and validates an ordered list.
// Duplicate addresses are rejected so configuration never silently changes
// priority or selects different transport identities for the same destination.
func NormalizeEndpoints(legacy string, endpoints []Endpoint) ([]Endpoint, error) {
	if legacy != "" {
		if len(endpoints) != 0 {
			return nil, fmt.Errorf("cannot configure both a processor address and processors list")
		}
		endpoints = []Endpoint{{Address: legacy}}
	}
	if len(endpoints) == 0 {
		return nil, nil
	}
	result := make([]Endpoint, len(endpoints))
	seen := make(map[string]Endpoint, len(endpoints))
	for i, endpoint := range endpoints {
		address, err := normalizeAddress(endpoint.Address)
		if err != nil {
			return nil, fmt.Errorf("processor candidate %d: %w", i+1, err)
		}
		endpoint.Address = address
		endpoint.TLSServerName = strings.TrimSpace(endpoint.TLSServerName)
		if endpoint.TLSServerName != "" && !validHost(endpoint.TLSServerName) {
			return nil, fmt.Errorf("processor candidate %d: invalid TLS server name %q", i+1, endpoint.TLSServerName)
		}
		if previous, exists := seen[address]; exists {
			if previous.TLSServerName != endpoint.TLSServerName {
				return nil, fmt.Errorf("duplicate processor %q has conflicting TLS server names", address)
			}
			return nil, fmt.Errorf("duplicate processor address %q", address)
		}
		seen[address] = endpoint
		result[i] = endpoint
	}
	return result, nil
}

func normalizeAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid processor address %q: expected host:port: %w", address, err)
	}
	if !validHost(host) {
		return "", fmt.Errorf("invalid processor host %q", host)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("invalid processor port %q: expected 1–65535", portText)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return net.JoinHostPort(host, strconv.FormatUint(port, 10)), nil
}

func validHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if ch != '-' && !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') {
				return false
			}
		}
	}
	return true
}
