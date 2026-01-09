//go:build cli || hunter || tap || all

package keylog

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// ErrInvalidFormat indicates a malformed key log line.
	ErrInvalidFormat = errors.New("invalid key log format")

	// ErrInvalidLabel indicates an unrecognized label.
	ErrInvalidLabel = errors.New("invalid key log label")

	// ErrInvalidClientRandom indicates an invalid client random value.
	ErrInvalidClientRandom = errors.New("invalid client random: must be 32 bytes (64 hex chars)")

	// ErrInvalidSecret indicates an invalid secret value.
	ErrInvalidSecret = errors.New("invalid secret value")
)

// Parser parses NSS Key Log format files.
type Parser struct {
	// StrictMode rejects entries with unknown labels.
	// When false (default), unknown labels are silently ignored.
	StrictMode bool
}

// NewParser creates a new key log parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseLine parses a single line from a key log file.
// Returns nil, nil for empty lines and comments.
// Returns the KeyEntry and nil on success.
// Returns nil and an error on parse failure.
func (p *Parser) ParseLine(line string) (*KeyEntry, error) {
	// Trim whitespace
	line = strings.TrimSpace(line)

	// Skip empty lines and comments
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	// Split into fields: <label> <client_random> <secret>
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return nil, fmt.Errorf("%w: expected 3 fields, got %d", ErrInvalidFormat, len(fields))
	}

	label := ParseLabel(fields[0])
	if label == LabelUnknown {
		if p.StrictMode {
			return nil, fmt.Errorf("%w: %s", ErrInvalidLabel, fields[0])
		}
		// Non-strict mode: skip unknown labels
		return nil, nil
	}

	// Parse client random (must be 32 bytes = 64 hex chars)
	clientRandomHex := strings.ToLower(fields[1])
	if len(clientRandomHex) != 64 {
		return nil, fmt.Errorf("%w: got %d hex chars", ErrInvalidClientRandom, len(clientRandomHex))
	}

	clientRandomBytes, err := hex.DecodeString(clientRandomHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientRandom, err)
	}

	var clientRandom [32]byte
	copy(clientRandom[:], clientRandomBytes)

	// Parse secret
	secretHex := strings.ToLower(fields[2])
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSecret, err)
	}

	// Validate secret length based on label
	if err := p.validateSecretLength(label, len(secret)); err != nil {
		return nil, err
	}

	return &KeyEntry{
		Label:        label,
		ClientRandom: clientRandom,
		Secret:       secret,
	}, nil
}

// validateSecretLength validates the secret length for the given label.
func (p *Parser) validateSecretLength(label LabelType, length int) error {
	switch label {
	case LabelClientRandom:
		// Pre-master secret is 48 bytes
		if length != 48 {
			return fmt.Errorf("%w: CLIENT_RANDOM secret must be 48 bytes, got %d", ErrInvalidSecret, length)
		}
	default:
		// TLS 1.3 secrets are 32 or 48 bytes depending on cipher suite hash
		// SHA-256 based = 32 bytes, SHA-384 based = 48 bytes
		if length != 32 && length != 48 {
			return fmt.Errorf("%w: TLS 1.3 secret must be 32 or 48 bytes, got %d", ErrInvalidSecret, length)
		}
	}
	return nil
}

// Parse reads and parses all entries from a reader.
// Returns all valid entries and any parse errors encountered.
// Parsing continues after errors to collect as many entries as possible.
func (p *Parser) Parse(r io.Reader) ([]*KeyEntry, []error) {
	var entries []*KeyEntry
	var errs []error

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		entry, err := p.ParseLine(scanner.Text())
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", lineNum, err))
			continue
		}
		if entry != nil {
			entries = append(entries, entry)
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Errorf("read error: %w", err))
	}

	return entries, errs
}

// ParseString parses entries from a string.
func (p *Parser) ParseString(s string) ([]*KeyEntry, []error) {
	return p.Parse(strings.NewReader(s))
}

// FormatEntry formats a KeyEntry back to NSS Key Log format.
func FormatEntry(entry *KeyEntry) string {
	return fmt.Sprintf("%s %s %s",
		entry.Label.String(),
		entry.ClientRandomHex(),
		entry.SecretHex(),
	)
}

// FormatEntries formats multiple entries to NSS Key Log format with newlines.
func FormatEntries(entries []*KeyEntry) string {
	var sb strings.Builder
	for _, entry := range entries {
		sb.WriteString(FormatEntry(entry))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// WriteEntries writes entries to a writer in NSS Key Log format.
func WriteEntries(w io.Writer, entries []*KeyEntry) error {
	for _, entry := range entries {
		if _, err := fmt.Fprintln(w, FormatEntry(entry)); err != nil {
			return err
		}
	}
	return nil
}
