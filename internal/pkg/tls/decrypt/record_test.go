//go:build cli || hunter || tap || all

package decrypt

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordParser_ParseSingleRecord(t *testing.T) {
	tests := []struct {
		name        string
		data        string // hex encoded
		wantType    uint8
		wantVersion uint16
		wantLen     int
		wantErr     bool
	}{
		{
			name: "valid handshake record",
			// TLS record: Handshake(22), TLS 1.2(0x0303), length 5, data "hello"
			data:        "160303000568656c6c6f",
			wantType:    ContentTypeHandshake,
			wantVersion: VersionTLS12,
			wantLen:     5,
			wantErr:     false,
		},
		{
			name: "valid application data record",
			// Application data(23), TLS 1.2, length 3
			data:        "17030300036162" + "63",
			wantType:    ContentTypeApplicationData,
			wantVersion: VersionTLS12,
			wantLen:     3,
			wantErr:     false,
		},
		{
			name: "valid alert record",
			// Alert(21), TLS 1.0, length 2
			data:        "1503010002" + "0146",
			wantType:    ContentTypeAlert,
			wantVersion: VersionTLS10,
			wantLen:     2,
			wantErr:     false,
		},
		{
			name: "valid change cipher spec",
			// ChangeCipherSpec(20), TLS 1.1, length 1
			data:        "14030200" + "0101",
			wantType:    ContentTypeChangeCipherSpec,
			wantVersion: VersionTLS11,
			wantLen:     1,
			wantErr:     false,
		},
		{
			name:    "invalid content type",
			data:    "FF0303000568656c6c6f",
			wantErr: true,
		},
		{
			name:    "invalid version",
			data:    "160401000568656c6c6f", // Version 4.1
			wantErr: true,
		},
		{
			name:    "insufficient data for header",
			data:    "16030300",
			wantErr: true,
		},
		{
			name:    "insufficient data for fragment",
			data:    "160303001068656c6c6f", // Claims 16 bytes but only has 5
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.data)
			require.NoError(t, err)

			record, err := ParseSingleRecord(data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, record)
			assert.Equal(t, tt.wantType, record.ContentType)
			assert.Equal(t, tt.wantVersion, record.Version)
			assert.Equal(t, tt.wantLen, len(record.Fragment))
		})
	}
}

func TestRecordParser_ParseRecords_Reassembly(t *testing.T) {
	parser := NewRecordParser()

	// Create two complete records
	record1 := mustDecodeHex(t, "160303000568656c6c6f")                    // "hello"
	record2 := append(mustDecodeHex(t, "170303000577"), []byte("orld")...) // "world"

	// Feed both records at once
	records, err := parser.ParseRecords(append(record1, record2...))
	require.NoError(t, err)
	assert.Len(t, records, 2)
	assert.Equal(t, uint8(ContentTypeHandshake), records[0].ContentType)
	assert.Equal(t, uint8(ContentTypeApplicationData), records[1].ContentType)
}

func TestRecordParser_ParseRecords_PartialData(t *testing.T) {
	parser := NewRecordParser()

	// Full record header + partial fragment
	fullRecord := mustDecodeHex(t, "160303000568656c6c6f") // 5 bytes fragment

	// Feed first part (header + 3 bytes)
	part1 := fullRecord[:8] // header(5) + 3 bytes
	records, err := parser.ParseRecords(part1)
	require.NoError(t, err)
	assert.Len(t, records, 0) // Not complete yet
	assert.Equal(t, 8, parser.BufferedBytes())

	// Feed remaining bytes
	part2 := fullRecord[8:]
	records, err = parser.ParseRecords(part2)
	require.NoError(t, err)
	assert.Len(t, records, 1)
	assert.Equal(t, "hello", string(records[0].Fragment))
	assert.Equal(t, 0, parser.BufferedBytes())
}

func TestRecordParser_Reset(t *testing.T) {
	parser := NewRecordParser()

	// Feed partial data
	partial := mustDecodeHex(t, "16030300")
	_, _ = parser.ParseRecords(partial)
	assert.Greater(t, parser.BufferedBytes(), 0)

	parser.Reset()
	assert.Equal(t, 0, parser.BufferedBytes())
}

func TestExtractClientRandom(t *testing.T) {
	// Minimal ClientHello structure:
	// Type(1) + Length(3) + Version(2) + Random(32) + ...
	// Type = 1 (ClientHello)
	clientHello := make([]byte, 44)
	clientHello[0] = 1 // ClientHello
	// Length = 40 (3 bytes, big-endian)
	clientHello[1] = 0
	clientHello[2] = 0
	clientHello[3] = 40
	// Version = TLS 1.2
	clientHello[4] = 0x03
	clientHello[5] = 0x03
	// Random = 32 bytes starting at offset 6
	expectedRandom := make([]byte, 32)
	for i := range expectedRandom {
		expectedRandom[i] = byte(i + 1)
	}
	copy(clientHello[6:38], expectedRandom)

	record := &Record{
		ContentType: ContentTypeHandshake,
		Fragment:    clientHello,
	}

	random := ExtractClientRandom(record)
	assert.Equal(t, expectedRandom, random)
}

func TestExtractServerRandom(t *testing.T) {
	// Minimal ServerHello structure
	serverHello := make([]byte, 44)
	serverHello[0] = 2 // ServerHello
	serverHello[1] = 0
	serverHello[2] = 0
	serverHello[3] = 40
	serverHello[4] = 0x03
	serverHello[5] = 0x03
	expectedRandom := make([]byte, 32)
	for i := range expectedRandom {
		expectedRandom[i] = byte(0xFF - i)
	}
	copy(serverHello[6:38], expectedRandom)

	record := &Record{
		ContentType: ContentTypeHandshake,
		Fragment:    serverHello,
	}

	random := ExtractServerRandom(record)
	assert.Equal(t, expectedRandom, random)
}

func TestExtractCipherSuite(t *testing.T) {
	// ServerHello with cipher suite at offset 39 (after session ID)
	serverHello := make([]byte, 50)
	serverHello[0] = 2 // ServerHello
	serverHello[1] = 0
	serverHello[2] = 0
	serverHello[3] = 46
	// Version
	serverHello[4] = 0x03
	serverHello[5] = 0x03
	// Random (32 bytes)
	// Session ID length = 0
	serverHello[38] = 0
	// Cipher suite at 39
	serverHello[39] = 0xc0
	serverHello[40] = 0x2f // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

	record := &Record{
		ContentType: ContentTypeHandshake,
		Fragment:    serverHello,
	}

	cipher := ExtractCipherSuite(record)
	assert.Equal(t, uint16(0xc02f), cipher)
}

func TestStreamReassembler(t *testing.T) {
	sr := NewStreamReassembler()

	clientRecord := mustDecodeHex(t, "160303000568656c6c6f")
	serverRecord := append(mustDecodeHex(t, "160303000577"), []byte("orld")...)

	clientRecords, err := sr.AddClientData(clientRecord)
	require.NoError(t, err)
	assert.Len(t, clientRecords, 1)

	serverRecords, err := sr.AddServerData(serverRecord)
	require.NoError(t, err)
	assert.Len(t, serverRecords, 1)

	sr.Reset()
	assert.Equal(t, 0, sr.ClientBuffered())
	assert.Equal(t, 0, sr.ServerBuffered())
}

func TestRecord_ContentTypeName(t *testing.T) {
	tests := []struct {
		ct   uint8
		name string
	}{
		{ContentTypeChangeCipherSpec, "ChangeCipherSpec"},
		{ContentTypeAlert, "Alert"},
		{ContentTypeHandshake, "Handshake"},
		{ContentTypeApplicationData, "ApplicationData"},
		{ContentTypeHeartbeat, "Heartbeat"},
		{99, "Unknown"},
	}

	for _, tt := range tests {
		record := &Record{ContentType: tt.ct}
		assert.Equal(t, tt.name, record.ContentTypeName())
	}
}

func TestVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		name    string
	}{
		{VersionSSL30, "SSL 3.0"},
		{VersionTLS10, "TLS 1.0"},
		{VersionTLS11, "TLS 1.1"},
		{VersionTLS12, "TLS 1.2"},
		{VersionTLS13, "TLS 1.3"},
		{0x0400, "Unknown"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.name, VersionName(tt.version))
	}
}

func TestDirection_String(t *testing.T) {
	assert.Equal(t, "client", DirectionClient.String())
	assert.Equal(t, "server", DirectionServer.String())
}

func TestSessionState_SequenceNumbers(t *testing.T) {
	state := &SessionState{}

	// Test client direction
	assert.Equal(t, uint64(0), state.GetSeqNum(DirectionClient))
	seq := state.IncrementSeqNum(DirectionClient)
	assert.Equal(t, uint64(0), seq)
	assert.Equal(t, uint64(1), state.GetSeqNum(DirectionClient))

	// Test server direction
	assert.Equal(t, uint64(0), state.GetSeqNum(DirectionServer))
	seq = state.IncrementSeqNum(DirectionServer)
	assert.Equal(t, uint64(0), seq)
	assert.Equal(t, uint64(1), state.GetSeqNum(DirectionServer))
}

func TestSessionState_EncryptionState(t *testing.T) {
	state := &SessionState{}

	assert.False(t, state.IsEncrypted(DirectionClient))
	assert.False(t, state.IsEncrypted(DirectionServer))

	state.SetEncrypted(DirectionClient, true)
	assert.True(t, state.IsEncrypted(DirectionClient))
	assert.False(t, state.IsEncrypted(DirectionServer))

	state.SetEncrypted(DirectionServer, true)
	assert.True(t, state.IsEncrypted(DirectionServer))
}

func TestGetCipherSuiteInfo(t *testing.T) {
	// Test known cipher suite
	info := GetCipherSuiteInfo(0xc02f) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	require.NotNil(t, info)
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", info.Name)
	assert.Equal(t, 16, info.KeyLen)
	assert.True(t, info.IsAEAD)
	assert.False(t, info.IsTLS13)

	// Test TLS 1.3 cipher suite
	info = GetCipherSuiteInfo(0x1301) // TLS_AES_128_GCM_SHA256
	require.NotNil(t, info)
	assert.True(t, info.IsTLS13)
	assert.True(t, info.IsAEAD)

	// Test unknown cipher suite
	info = GetCipherSuiteInfo(0xFFFF)
	assert.Nil(t, info)
}

func TestIsSupportedCipherSuite(t *testing.T) {
	assert.True(t, IsSupportedCipherSuite(0xc02f))
	assert.True(t, IsSupportedCipherSuite(0x1301))
	assert.False(t, IsSupportedCipherSuite(0xFFFF))
}

// mustDecodeHex is in kdf_test.go
