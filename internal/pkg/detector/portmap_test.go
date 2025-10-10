package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPortMap_BuildsCorrectly(t *testing.T) {
	d := New()

	// Register some signatures
	dnsSignature := &MockSignature{
		name:      "DNS Detector",
		protocols: []string{"DNS"},
		priority:  100,
	}
	httpSignature := &MockSignature{
		name:      "HTTP Detector",
		protocols: []string{"HTTP"},
		priority:  80,
	}

	d.RegisterSignature(dnsSignature)
	d.RegisterSignature(httpSignature)

	// Verify port map was built
	assert.NotNil(t, d.portMap)
	assert.Equal(t, 3, len(d.portMap)) // DNS:53, HTTP:80, HTTP:8080

	// Verify port 53 maps to DNS detector
	dnsSig := d.getPortHint(53)
	assert.NotNil(t, dnsSig)
	assert.Equal(t, "DNS Detector", dnsSig.Name())

	// Verify port 80 maps to HTTP detector
	httpSig := d.getPortHint(80)
	assert.NotNil(t, httpSig)
	assert.Equal(t, "HTTP Detector", httpSig.Name())

	// Verify port 8080 maps to HTTP detector
	httpAltSig := d.getPortHint(8080)
	assert.NotNil(t, httpAltSig)
	assert.Equal(t, "HTTP Detector", httpAltSig.Name())

	// Verify unknown port returns nil
	unknownSig := d.getPortHint(9999)
	assert.Nil(t, unknownSig)
}

func TestPortMap_FastLookup(t *testing.T) {
	d := New()

	// Register multiple signatures
	signatures := []*MockSignature{
		{name: "DNS Detector", protocols: []string{"DNS"}, priority: 100},
		{name: "HTTP Detector", protocols: []string{"HTTP"}, priority: 90},
		{name: "TLS/SSL Detector", protocols: []string{"TLS"}, priority: 80},
		{name: "SSH Detector", protocols: []string{"SSH"}, priority: 70},
		{name: "MySQL Detector", protocols: []string{"MySQL"}, priority: 60},
		{name: "PostgreSQL Detector", protocols: []string{"PostgreSQL"}, priority: 50},
	}

	for _, sig := range signatures {
		d.RegisterSignature(sig)
	}

	// Verify fast O(1) lookup works for all registered ports
	testCases := []struct {
		port     uint16
		expected string
	}{
		{53, "DNS Detector"},
		{80, "HTTP Detector"},
		{443, "TLS/SSL Detector"},
		{22, "SSH Detector"},
		{3306, "MySQL Detector"},
		{5432, "PostgreSQL Detector"},
		{9999, ""}, // Unknown port
	}

	for _, tc := range testCases {
		sig := d.getPortHint(tc.port)
		if tc.expected == "" {
			assert.Nil(t, sig, "port %d should not have a signature", tc.port)
		} else {
			assert.NotNil(t, sig, "port %d should have a signature", tc.port)
			assert.Equal(t, tc.expected, sig.Name(), "port %d mapped to wrong signature", tc.port)
		}
	}
}

func TestPortMap_FirstRegisteredWins(t *testing.T) {
	d := New()

	// Register two signatures that might claim the same port
	// (in reality this shouldn't happen, but test the behavior)
	sig1 := &MockSignature{
		name:      "HTTP Detector",
		protocols: []string{"HTTP"},
		priority:  100,
	}
	sig2 := &MockSignature{
		name:      "gRPC/HTTP2 Detector",
		protocols: []string{"gRPC"},
		priority:  90,
	}

	d.RegisterSignature(sig1)
	d.RegisterSignature(sig2)

	// Port 80 should map to HTTP (registered first)
	sig := d.getPortHint(80)
	assert.NotNil(t, sig)
	assert.Equal(t, "HTTP Detector", sig.Name())

	// Port 8080 should also map to HTTP (registered first)
	sig = d.getPortHint(8080)
	assert.NotNil(t, sig)
	assert.Equal(t, "HTTP Detector", sig.Name())
}

func TestGetSignaturePorts_AllKnownSignatures(t *testing.T) {
	d := New()

	testCases := []struct {
		sigName       string
		expectedPorts []uint16
	}{
		{"DNS Detector", []uint16{53}},
		{"HTTP Detector", []uint16{80, 8080}},
		{"TLS/SSL Detector", []uint16{443, 8443}},
		{"SSH Detector", []uint16{22}},
		{"FTP Detector", []uint16{21, 20}},
		{"SMTP Detector", []uint16{25, 587}},
		{"POP3 Detector", []uint16{110, 995}},
		{"IMAP Detector", []uint16{143, 993}},
		{"MySQL Detector", []uint16{3306}},
		{"PostgreSQL Detector", []uint16{5432}},
		{"Redis Detector", []uint16{6379}},
		{"MongoDB Detector", []uint16{27017}},
		{"SIP Detector", []uint16{5060, 5061}},
		{"RTP Detector", nil}, // Dynamic ports
		{"Telnet Detector", []uint16{23}},
		{"SNMP Detector", []uint16{161, 162}},
		{"NTP Detector", []uint16{123}},
		{"DHCP Detector", []uint16{67, 68}},
		{"Unknown Detector", nil},
	}

	for _, tc := range testCases {
		sig := &MockSignature{name: tc.sigName}
		ports := d.getSignaturePorts(sig)
		assert.Equal(t, tc.expectedPorts, ports, "ports mismatch for %s", tc.sigName)
	}
}

func TestPortMap_ConcurrentAccess(t *testing.T) {
	d := New()

	// Register signatures
	for i := 0; i < 10; i++ {
		sig := &MockSignature{
			name:      "DNS Detector",
			protocols: []string{"DNS"},
			priority:  100,
		}
		d.RegisterSignature(sig)
	}

	// Concurrent reads should be safe (read lock)
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			sig := d.getPortHint(53)
			assert.NotNil(t, sig)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
}
