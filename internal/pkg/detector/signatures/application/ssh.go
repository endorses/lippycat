package application

import (
	"bytes"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/simd"
)

// SSHSignature detects SSH (Secure Shell) protocol
type SSHSignature struct {
	versionPrefix []byte
}

// NewSSHSignature creates a new SSH signature detector
func NewSSHSignature() *SSHSignature {
	return &SSHSignature{
		versionPrefix: []byte("SSH-"),
	}
}

func (s *SSHSignature) Name() string {
	return "SSH Detector"
}

func (s *SSHSignature) Protocols() []string {
	return []string{"SSH"}
}

func (s *SSHSignature) Priority() int {
	return 100 // High priority for security protocol
}

func (s *SSHSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (s *SSHSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if len(ctx.Payload) < 7 {
		return nil
	}

	// SSH version string: "SSH-2.0-" or "SSH-1.99-" or "SSH-1.5-"
	// Format: SSH-protoversion-softwareversion comments
	if !simd.BytesEqual(ctx.Payload[:4], s.versionPrefix) {
		return nil
	}

	// Find end of version line (CR or LF)
	endIdx := bytes.IndexAny(ctx.Payload, "\r\n")
	if endIdx == -1 {
		// No newline found, check if we have enough for basic detection
		if len(ctx.Payload) < 20 {
			return nil
		}
		endIdx = min(len(ctx.Payload), 100)
	}

	versionLine := string(ctx.Payload[:endIdx])

	// Parse version: SSH-<proto>-<software> <comments>
	parts := strings.SplitN(versionLine, "-", 3)
	if len(parts) < 3 {
		return nil
	}

	protoVersion := parts[1]
	softwareRest := parts[2]

	// Split software and comments
	softwareParts := strings.SplitN(softwareRest, " ", 2)
	software := softwareParts[0]
	comments := ""
	if len(softwareParts) > 1 {
		comments = softwareParts[1]
	}

	metadata := map[string]interface{}{
		"type":            "protocol_version",
		"version_string":  versionLine,
		"proto_version":   protoVersion,
		"software":        software,
	}

	if comments != "" {
		metadata["comments"] = comments
	}

	// Validate protocol version
	if protoVersion != "2.0" && protoVersion != "1.99" && protoVersion != "1.5" {
		// Unknown SSH version, lower confidence
		metadata["valid_version"] = false
	} else {
		metadata["valid_version"] = true
	}

	// Calculate confidence
	confidence := s.calculateConfidence(ctx, metadata, protoVersion)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{22})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{22})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "SSH",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (s *SSHSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, protoVersion string) float64 {
	indicators := []signatures.Indicator{
		{Name: "ssh_prefix", Weight: 0.5, Confidence: signatures.ConfidenceVeryHigh},
	}

	// Valid protocol version
	if validVer, ok := metadata["valid_version"].(bool); ok && validVer {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_version",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// TCP transport (SSH is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}
