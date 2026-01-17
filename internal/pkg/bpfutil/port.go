// Package bpfutil provides utilities for BPF filter construction.
package bpfutil

import (
	"net"
)

// ExtractPortFromAddr extracts the port from a "host:port" address string.
// Returns empty string if the address is empty, invalid, or has no port.
// Handles both IPv4 ("host:port") and IPv6 ("[::1]:port") formats.
func ExtractPortFromAddr(addr string) string {
	if addr == "" {
		return ""
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}

	return port
}
