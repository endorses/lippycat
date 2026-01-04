package email

import (
	"fmt"
	"strconv"
	"strings"
)

// FilterBuilder builds BPF filters for email protocol capture.
type FilterBuilder struct{}

// NewFilterBuilder creates a new email filter builder.
func NewFilterBuilder() *FilterBuilder {
	return &FilterBuilder{}
}

// FilterConfig holds email filter configuration.
type FilterConfig struct {
	// Ports is a list of SMTP ports to capture (default: 25, 465, 587)
	Ports []uint16

	// Protocol specifies which email protocol to capture
	// "smtp", "imap", "pop3", or "all" (default: "all")
	Protocol string

	// BaseFilter is an additional filter to combine with email filter
	BaseFilter string
}

// DefaultFilterConfig returns the default filter configuration.
func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		Ports:    DefaultSMTPPorts,
		Protocol: "smtp",
	}
}

// Build creates a BPF filter string for email capture.
func (fb *FilterBuilder) Build(config FilterConfig) string {
	ports := config.Ports
	if len(ports) == 0 {
		ports = DefaultSMTPPorts
	}

	// Build port filter
	portFilter := fb.buildPortFilter(ports)

	// Email protocols use TCP only
	filter := fmt.Sprintf("tcp and (%s)", portFilter)

	// Combine with base filter if provided
	if config.BaseFilter != "" {
		filter = fmt.Sprintf("(%s) and (%s)", filter, config.BaseFilter)
	}

	return filter
}

// buildPortFilter builds port matching expression.
func (fb *FilterBuilder) buildPortFilter(ports []uint16) string {
	if len(ports) == 1 {
		return fmt.Sprintf("port %d", ports[0])
	}

	var portStrs []string
	for _, p := range ports {
		portStrs = append(portStrs, fmt.Sprintf("port %d", p))
	}
	return strings.Join(portStrs, " or ")
}

// ParsePorts parses a comma-separated list of ports.
func ParsePorts(portsStr string) ([]uint16, error) {
	if portsStr == "" {
		return DefaultSMTPPorts, nil
	}

	var ports []uint16
	for _, p := range strings.Split(portsStr, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		if port == 0 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range", port)
		}
		ports = append(ports, uint16(port))
	}

	if len(ports) == 0 {
		return DefaultSMTPPorts, nil
	}
	return ports, nil
}

// Standard email ports.
const (
	SMTPPort           = 25  // Standard SMTP
	SMTPSubmissionPort = 587 // SMTP submission
	SMTPSPort          = 465 // SMTP over TLS (SMTPS)
	IMAPPort           = 143 // Standard IMAP
	IMAPSPort          = 993 // IMAP over TLS
	POP3Port           = 110 // Standard POP3
	POP3SPort          = 995 // POP3 over TLS
)

// DefaultSMTPPorts includes standard SMTP ports.
var DefaultSMTPPorts = []uint16{
	SMTPPort,           // 25 - Standard SMTP
	SMTPSubmissionPort, // 587 - SMTP submission
	SMTPSPort,          // 465 - SMTPS
}

// DefaultIMAPPorts includes standard IMAP ports.
var DefaultIMAPPorts = []uint16{
	IMAPPort,  // 143 - Standard IMAP
	IMAPSPort, // 993 - IMAPS
}

// DefaultPOP3Ports includes standard POP3 ports.
var DefaultPOP3Ports = []uint16{
	POP3Port,  // 110 - Standard POP3
	POP3SPort, // 995 - POP3S
}

// AllEmailPorts includes all standard email ports.
var AllEmailPorts = []uint16{
	SMTPPort, SMTPSubmissionPort, SMTPSPort,
	IMAPPort, IMAPSPort,
	POP3Port, POP3SPort,
}

// IsSMTPPort checks if a port is a standard SMTP port.
func IsSMTPPort(port uint16) bool {
	return port == SMTPPort || port == SMTPSubmissionPort || port == SMTPSPort
}

// IsIMAPPort checks if a port is a standard IMAP port.
func IsIMAPPort(port uint16) bool {
	return port == IMAPPort || port == IMAPSPort
}

// IsPOP3Port checks if a port is a standard POP3 port.
func IsPOP3Port(port uint16) bool {
	return port == POP3Port || port == POP3SPort
}
