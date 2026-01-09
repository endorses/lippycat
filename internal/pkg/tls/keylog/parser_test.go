//go:build cli || hunter || processor || tap || all

package keylog

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sample key log data for testing
const sampleKeyLog = `# TLS 1.2 session
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

# TLS 1.3 session
CLIENT_HANDSHAKE_TRAFFIC_SECRET fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
SERVER_HANDSHAKE_TRAFFIC_SECRET fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
CLIENT_TRAFFIC_SECRET_0 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff
SERVER_TRAFFIC_SECRET_0 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa
`

func TestParseLabelType(t *testing.T) {
	tests := []struct {
		input    string
		expected LabelType
	}{
		{"CLIENT_RANDOM", LabelClientRandom},
		{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", LabelClientHandshakeTrafficSecret},
		{"SERVER_HANDSHAKE_TRAFFIC_SECRET", LabelServerHandshakeTrafficSecret},
		{"CLIENT_TRAFFIC_SECRET_0", LabelClientTrafficSecret0},
		{"SERVER_TRAFFIC_SECRET_0", LabelServerTrafficSecret0},
		{"EXPORTER_SECRET", LabelExporterSecret},
		{"EARLY_EXPORTER_SECRET", LabelEarlyExporterSecret},
		{"CLIENT_EARLY_TRAFFIC_SECRET", LabelClientEarlyTrafficSecret},
		{"UNKNOWN_LABEL", LabelUnknown},
		{"", LabelUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseLabel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLabelTypeString(t *testing.T) {
	tests := []struct {
		label    LabelType
		expected string
	}{
		{LabelClientRandom, "CLIENT_RANDOM"},
		{LabelClientHandshakeTrafficSecret, "CLIENT_HANDSHAKE_TRAFFIC_SECRET"},
		{LabelServerHandshakeTrafficSecret, "SERVER_HANDSHAKE_TRAFFIC_SECRET"},
		{LabelClientTrafficSecret0, "CLIENT_TRAFFIC_SECRET_0"},
		{LabelServerTrafficSecret0, "SERVER_TRAFFIC_SECRET_0"},
		{LabelExporterSecret, "EXPORTER_SECRET"},
		{LabelEarlyExporterSecret, "EARLY_EXPORTER_SECRET"},
		{LabelClientEarlyTrafficSecret, "CLIENT_EARLY_TRAFFIC_SECRET"},
		{LabelUnknown, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.label.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLabelTypeIsTLS13(t *testing.T) {
	assert.False(t, LabelClientRandom.IsTLS13())
	assert.False(t, LabelUnknown.IsTLS13())

	assert.True(t, LabelClientHandshakeTrafficSecret.IsTLS13())
	assert.True(t, LabelServerHandshakeTrafficSecret.IsTLS13())
	assert.True(t, LabelClientTrafficSecret0.IsTLS13())
	assert.True(t, LabelServerTrafficSecret0.IsTLS13())
	assert.True(t, LabelExporterSecret.IsTLS13())
	assert.True(t, LabelEarlyExporterSecret.IsTLS13())
	assert.True(t, LabelClientEarlyTrafficSecret.IsTLS13())
}

func TestParserParseLine(t *testing.T) {
	p := NewParser()

	t.Run("valid CLIENT_RANDOM line", func(t *testing.T) {
		line := "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
		entry, err := p.ParseLine(line)
		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, LabelClientRandom, entry.Label)
		assert.Equal(t, 48, len(entry.Secret))
	})

	t.Run("valid TLS 1.3 line", func(t *testing.T) {
		line := "CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
		entry, err := p.ParseLine(line)
		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, LabelClientTrafficSecret0, entry.Label)
		assert.Equal(t, 32, len(entry.Secret))
	})

	t.Run("empty line", func(t *testing.T) {
		entry, err := p.ParseLine("")
		require.NoError(t, err)
		assert.Nil(t, entry)
	})

	t.Run("comment line", func(t *testing.T) {
		entry, err := p.ParseLine("# This is a comment")
		require.NoError(t, err)
		assert.Nil(t, entry)
	})

	t.Run("whitespace only", func(t *testing.T) {
		entry, err := p.ParseLine("   \t  ")
		require.NoError(t, err)
		assert.Nil(t, entry)
	})

	t.Run("unknown label non-strict", func(t *testing.T) {
		p.StrictMode = false
		entry, err := p.ParseLine("UNKNOWN_LABEL 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef aabbccdd")
		require.NoError(t, err)
		assert.Nil(t, entry) // Should be silently ignored
	})

	t.Run("unknown label strict", func(t *testing.T) {
		p.StrictMode = true
		_, err := p.ParseLine("UNKNOWN_LABEL 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef aabbccdd")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidLabel)
		p.StrictMode = false
	})

	t.Run("wrong field count", func(t *testing.T) {
		_, err := p.ParseLine("CLIENT_RANDOM only_two_fields")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidFormat)
	})

	t.Run("invalid client random length", func(t *testing.T) {
		_, err := p.ParseLine("CLIENT_RANDOM 0123 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidClientRandom)
	})

	t.Run("invalid client random hex", func(t *testing.T) {
		_, err := p.ParseLine("CLIENT_RANDOM gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidClientRandom)
	})

	t.Run("invalid pre-master secret length", func(t *testing.T) {
		_, err := p.ParseLine("CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 00112233")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSecret)
	})

	t.Run("uppercase hex is accepted", func(t *testing.T) {
		line := "CLIENT_RANDOM 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
		entry, err := p.ParseLine(line)
		require.NoError(t, err)
		require.NotNil(t, entry)
	})
}

func TestParserParse(t *testing.T) {
	p := NewParser()

	t.Run("parse multiple entries", func(t *testing.T) {
		entries, errs := p.Parse(strings.NewReader(sampleKeyLog))
		assert.Empty(t, errs)
		assert.Len(t, entries, 5)

		// Check first entry (TLS 1.2)
		assert.Equal(t, LabelClientRandom, entries[0].Label)
		assert.Equal(t, 48, len(entries[0].Secret))

		// Check TLS 1.3 entries
		assert.Equal(t, LabelClientHandshakeTrafficSecret, entries[1].Label)
		assert.Equal(t, LabelServerHandshakeTrafficSecret, entries[2].Label)
		assert.Equal(t, LabelClientTrafficSecret0, entries[3].Label)
		assert.Equal(t, LabelServerTrafficSecret0, entries[4].Label)
	})

	t.Run("parse with errors", func(t *testing.T) {
		input := `CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
INVALID_LINE
CLIENT_TRAFFIC_SECRET_0 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff
`
		p.StrictMode = true
		entries, errs := p.Parse(strings.NewReader(input))
		assert.Len(t, entries, 2) // Valid entries still parsed
		assert.Len(t, errs, 1)    // One error
		p.StrictMode = false
	})
}

func TestParserParseString(t *testing.T) {
	p := NewParser()
	entries, errs := p.ParseString(sampleKeyLog)
	assert.Empty(t, errs)
	assert.Len(t, entries, 5)
}

func TestFormatEntry(t *testing.T) {
	entry := &KeyEntry{
		Label:        LabelClientRandom,
		ClientRandom: [32]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		Secret:       make([]byte, 48),
	}

	result := FormatEntry(entry)
	assert.True(t, strings.HasPrefix(result, "CLIENT_RANDOM "))
	assert.Contains(t, result, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
}

func TestRoundTrip(t *testing.T) {
	p := NewParser()

	// Parse original
	entries, errs := p.ParseString(sampleKeyLog)
	require.Empty(t, errs)

	// Format back
	formatted := FormatEntries(entries)

	// Parse again
	entries2, errs2 := p.ParseString(formatted)
	require.Empty(t, errs2)
	assert.Len(t, entries2, len(entries))

	// Compare
	for i := range entries {
		assert.Equal(t, entries[i].Label, entries2[i].Label)
		assert.Equal(t, entries[i].ClientRandom, entries2[i].ClientRandom)
		assert.Equal(t, entries[i].Secret, entries2[i].Secret)
	}
}

func TestKeyEntryHexMethods(t *testing.T) {
	entry := &KeyEntry{
		Label:        LabelClientRandom,
		ClientRandom: [32]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		Secret:       []byte{0xaa, 0xbb, 0xcc, 0xdd},
	}

	assert.Equal(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", entry.ClientRandomHex())
	assert.Equal(t, "aabbccdd", entry.SecretHex())
}

func TestSessionKeysAddEntry(t *testing.T) {
	keys := &SessionKeys{}

	// Add TLS 1.2 key
	keys.AddEntry(&KeyEntry{
		Label:  LabelClientRandom,
		Secret: make([]byte, 48),
	})
	assert.True(t, keys.IsTLS12())
	assert.False(t, keys.IsTLS13())
	assert.True(t, keys.HasDecryptionKeys())

	// Add TLS 1.3 keys
	keys2 := &SessionKeys{}
	keys2.AddEntry(&KeyEntry{
		Label:  LabelClientTrafficSecret0,
		Secret: make([]byte, 32),
	})
	keys2.AddEntry(&KeyEntry{
		Label:  LabelServerTrafficSecret0,
		Secret: make([]byte, 32),
	})
	assert.False(t, keys2.IsTLS12())
	assert.True(t, keys2.IsTLS13())
	assert.True(t, keys2.HasDecryptionKeys())

	// Incomplete TLS 1.3
	keys3 := &SessionKeys{}
	keys3.AddEntry(&KeyEntry{
		Label:  LabelClientTrafficSecret0,
		Secret: make([]byte, 32),
	})
	assert.False(t, keys3.HasDecryptionKeys())
}
