package application

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// RedisSignature detects Redis protocol traffic (RESP - REdis Serialization Protocol)
type RedisSignature struct{}

// NewRedisSignature creates a new Redis signature detector
func NewRedisSignature() *RedisSignature {
	return &RedisSignature{}
}

func (r *RedisSignature) Name() string {
	return "Redis Detector"
}

func (r *RedisSignature) Protocols() []string {
	return []string{"Redis"}
}

func (r *RedisSignature) Priority() int {
	return 90 // High priority for database protocol
}

func (r *RedisSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (r *RedisSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// Redis uses RESP (REdis Serialization Protocol)
	// Format: First byte indicates type, followed by data and CRLF
	// Types:
	// + Simple String
	// - Error
	// : Integer
	// $ Bulk String
	// * Array

	if len(ctx.Payload) < 3 {
		return nil
	}

	payload := ctx.Payload

	// Check for valid RESP type indicator
	firstByte := payload[0]
	if !r.isValidRESPType(firstByte) {
		return nil
	}

	// Check for CRLF termination
	if !bytes.Contains(payload[:min(len(payload), 100)], []byte("\r\n")) {
		return nil
	}

	// Parse the RESP message
	respType := r.respTypeToString(firstByte)

	metadata := map[string]interface{}{
		"resp_type": respType,
	}

	// Try to extract command from array format
	// Redis commands are typically sent as arrays: *<count>\r\n$<len>\r\n<cmd>\r\n...
	if firstByte == '*' {
		if cmd := r.extractCommand(payload); cmd != "" {
			metadata["command"] = cmd
		}
	} else if firstByte == '+' || firstByte == '-' {
		// Simple string or error - extract the message
		lines := bytes.Split(payload[:min(len(payload), 200)], []byte("\r\n"))
		if len(lines) > 0 {
			msg := string(lines[0][1:]) // Skip first byte (type indicator)
			if len(msg) > 0 {
				metadata["message"] = msg
				if firstByte == '-' {
					metadata["error"] = true
				}
			}
		}
	} else if firstByte == ':' {
		// Integer
		lines := bytes.Split(payload[:min(len(payload), 50)], []byte("\r\n"))
		if len(lines) > 0 {
			numStr := string(lines[0][1:])
			if num, err := strconv.ParseInt(numStr, 10, 64); err == nil {
				metadata["value"] = num
			}
		}
	}

	// Calculate confidence
	confidence := r.calculateConfidence(ctx, metadata, firstByte)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{6379})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{6379})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "Redis",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (r *RedisSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, firstByte byte) float64 {
	indicators := []signatures.Indicator{
		{Name: "valid_resp_type", Weight: 0.6, Confidence: signatures.ConfidenceHigh},
	}

	// Known Redis command
	if _, hasCmd := metadata["command"]; hasCmd {
		indicators = append(indicators, signatures.Indicator{
			Name:       "known_command",
			Weight:     0.2,
			Confidence: signatures.ConfidenceVeryHigh,
		})
	}

	// TCP transport (Redis is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (r *RedisSignature) isValidRESPType(b byte) bool {
	return b == '+' || b == '-' || b == ':' || b == '$' || b == '*'
}

func (r *RedisSignature) respTypeToString(b byte) string {
	types := map[byte]string{
		'+': "Simple String",
		'-': "Error",
		':': "Integer",
		'$': "Bulk String",
		'*': "Array",
	}
	if t, ok := types[b]; ok {
		return t
	}
	return "Unknown"
}

func (r *RedisSignature) extractCommand(payload []byte) string {
	// Redis commands are typically: *<count>\r\n$<len>\r\n<command>\r\n...
	// Example: *2\r\n$3\r\nGET\r\n$3\r\nkey\r\n

	lines := bytes.Split(payload[:min(len(payload), 200)], []byte("\r\n"))
	if len(lines) < 3 {
		return ""
	}

	// First line should be *<count>
	if len(lines[0]) < 2 || lines[0][0] != '*' {
		return ""
	}

	// Second line should be $<length>
	if len(lines[1]) < 2 || lines[1][0] != '$' {
		return ""
	}

	// Third line is the command
	if len(lines[2]) > 0 {
		cmd := strings.ToUpper(string(lines[2]))
		// Validate it's a known Redis command
		if r.isKnownRedisCommand(cmd) {
			return cmd
		}
	}

	return ""
}

func (r *RedisSignature) isKnownRedisCommand(cmd string) bool {
	// Common Redis commands
	commands := map[string]bool{
		"GET": true, "SET": true, "DEL": true, "EXISTS": true,
		"INCR": true, "DECR": true, "LPUSH": true, "RPUSH": true,
		"LPOP": true, "RPOP": true, "SADD": true, "SREM": true,
		"ZADD": true, "ZREM": true, "HGET": true, "HSET": true,
		"PING": true, "ECHO": true, "AUTH": true, "SELECT": true,
		"KEYS": true, "SCAN": true, "FLUSHDB": true, "FLUSHALL": true,
		"PUBLISH": true, "SUBSCRIBE": true, "UNSUBSCRIBE": true,
		"MULTI": true, "EXEC": true, "DISCARD": true, "WATCH": true,
		"UNWATCH": true, "EXPIRE": true, "TTL": true, "PERSIST": true,
		"RENAME": true, "RENAMENX": true, "TYPE": true, "APPEND": true,
		"STRLEN": true, "GETRANGE": true, "SETRANGE": true, "GETBIT": true,
		"SETBIT": true, "BITCOUNT": true, "LLEN": true, "LRANGE": true,
		"LINDEX": true, "LSET": true, "SMEMBERS": true, "SCARD": true,
		"SISMEMBER": true, "ZRANGE": true, "ZCARD": true, "ZSCORE": true,
		"HGETALL": true, "HKEYS": true, "HVALS": true, "HDEL": true,
		"INFO": true, "CONFIG": true, "SAVE": true, "BGSAVE": true,
		"SHUTDOWN": true, "CLIENT": true, "CLUSTER": true, "DBSIZE": true,
	}
	return commands[cmd]
}
