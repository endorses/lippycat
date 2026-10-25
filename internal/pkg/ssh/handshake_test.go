package ssh

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKEXPayload(lists [10]string) []byte {
	payload := make([]byte, 17)
	payload[0] = 20
	for _, list := range lists {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(list)))
		payload = append(payload, list...)
	}
	return append(payload, 0, 0, 0, 0, 0)
}

func asymmetricLists() [10]string {
	return [10]string{"curve25519-sha256,ext-info-c", "ssh-ed25519", "aes128-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-512", "none", "zlib@openssh.com,none", "", ""}
}

func testPacket(payload []byte) []byte {
	padding := 8 - (5+len(payload))%8
	if padding < 4 {
		padding += 8
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+padding))
	packet = append(packet, byte(padding))
	packet = append(packet, payload...)
	return append(packet, make([]byte, padding)...)
}

func TestHASSHReferenceClient(t *testing.T) {
	// Published Cyberduck 6.7.1 vector and expected HASSH from the maintained
	// Corelight reference README. These are algorithm identifiers, not code.
	// https://github.com/corelight/hassh#example-1-client-fingerprinting---the-hassh
	lists := asymmetricLists()
	lists[0] = "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256@ssh.com,diffie-hellman-group15-sha256,diffie-hellman-group15-sha256@ssh.com,diffie-hellman-group15-sha384@ssh.com,diffie-hellman-group16-sha256,diffie-hellman-group16-sha384@ssh.com,diffie-hellman-group16-sha512@ssh.com,diffie-hellman-group18-sha512@ssh.com"
	lists[2] = "aes128-cbc,aes128-ctr,aes192-cbc,aes192-ctr,aes256-cbc,aes256-ctr,blowfish-cbc,blowfish-ctr,cast128-cbc,cast128-ctr,idea-cbc,idea-ctr,serpent128-cbc,serpent128-ctr,serpent192-cbc,serpent192-ctr,serpent256-cbc,serpent256-ctr,3des-cbc,3des-ctr,twofish128-cbc,twofish128-ctr,twofish192-cbc,twofish192-ctr,twofish256-cbc,twofish256-ctr,twofish-cbc,arcfour,arcfour128,arcfour256"
	lists[4] = "hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-sha2-256,hmac-sha2-512"
	lists[6] = "zlib@openssh.com,zlib,none"
	kex, err := ParseKEXINIT(testKEXPayload(lists))
	require.NoError(t, err)
	fp, available := kex.Fingerprint(RoleClient)
	require.True(t, available)
	require.Equal(t, "1.0", fp.Version)
	require.Equal(t, "8a8ae540028bf433cd68356c1b9e8d5b", fp.Hash)
	require.Equal(t, strings.Join([]string{lists[0], lists[2], lists[4], lists[6]}, ";"), fp.Algorithms)
}

func TestHASSHReferenceServer(t *testing.T) {
	// OpenSSH 5.3 server lists from the same reference's Example 2. Expected
	// digest independently calculated with Python hashlib and the reference's
	// kex;encryptionS2C;macS2C;compressionS2C method, outside this Go parser.
	lists := asymmetricLists()
	lists[0] = "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
	lists[3] = "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se"
	lists[5] = "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96"
	lists[7] = "none,zlib@openssh.com"
	kex, err := ParseKEXINIT(testKEXPayload(lists))
	require.NoError(t, err)
	fp, available := kex.Fingerprint(RoleServer)
	require.True(t, available)
	require.Equal(t, "b1c6c0d56317555b85c7005a3de29325", fp.Hash)
	require.Equal(t, strings.Join([]string{lists[0], lists[3], lists[5], lists[7]}, ";"), fp.Algorithms)
}

func TestHASSHRoleAndOrdering(t *testing.T) {
	payload := testKEXPayload(asymmetricLists())
	kex, err := ParseKEXINIT(payload)
	require.NoError(t, err)
	client, ok := kex.Fingerprint(RoleClient)
	require.True(t, ok)
	require.Equal(t, "cafb69eb1dbb2a4a505b5b25342a4940", client.Hash)
	server, ok := kex.Fingerprint(RoleServer)
	require.True(t, ok)
	require.Equal(t, "bb851e03510687da787151f064db2868", server.Hash)
	_, ok = kex.Fingerprint(RoleUnknown)
	require.False(t, ok)
	_, ok = (&KEXINIT{}).Fingerprint(RoleClient)
	require.False(t, ok)
	lists := asymmetricLists()
	lists[0] = "ext-info-c,curve25519-sha256"
	reordered, err := ParseKEXINIT(testKEXPayload(lists))
	require.NoError(t, err)
	fp, ok := reordered.Fingerprint(RoleClient)
	require.True(t, ok)
	require.NotEqual(t, client.Hash, fp.Hash)
	// Cookie, server host-key algorithms and follows flag are not hash inputs.
	payload[1], payload[len(payload)-5] = 255, 1
	withCookie, err := ParseKEXINIT(payload)
	require.NoError(t, err)
	fp, ok = withCookie.Fingerprint(RoleClient)
	require.True(t, ok)
	require.Equal(t, client, fp)
	for _, flag := range []byte{0, 1, 2, 255} {
		payload[len(payload)-5] = flag
		parsed, err := ParseKEXINIT(payload)
		require.NoError(t, err)
		require.Equal(t, flag != 0, parsed.FirstKEXPacketFollows)
		fp, ok := parsed.Fingerprint(RoleClient)
		require.True(t, ok)
		require.Equal(t, client.Hash, fp.Hash)
	}
	lists = asymmetricLists()
	lists[8] = "x-" + strings.Repeat("abc-", 24) + "abc"
	withLanguage, err := ParseKEXINIT(testKEXPayload(lists))
	require.NoError(t, err)
	fp, ok = withLanguage.Fingerprint(RoleClient)
	require.True(t, ok)
	require.Equal(t, client.Hash, fp.Hash)
}

func TestInitialHandshakeEverySplitAndOwnedData(t *testing.T) {
	wire := append([]byte("notice before server identification\r\nSSH-2.0-fixture optional comment\r\n"), testPacket(testKEXPayload(asymmetricLists()))...)
	for split := 0; split <= len(wire); split++ {
		var stream Stream
		var observations []Observation
		emit := func(o Observation) { observations = append(observations, o) }
		input := append([]byte(nil), wire...)
		require.NoError(t, stream.Feed(input[:split], emit))
		require.NoError(t, stream.Feed(input[split:], emit))
		clear(input)
		require.Equal(t, StopKEXComplete, stream.End())
		require.Zero(t, stream.BufferedBytes())
		require.Len(t, observations, 2)
		require.Equal(t, "SSH-2.0-fixture optional comment", observations[0].Identification.Banner)
		fp, ok := observations[1].KEXINIT.Fingerprint(RoleClient)
		require.True(t, ok)
		require.Equal(t, "cafb69eb1dbb2a4a505b5b25342a4940", fp.Hash)
		require.NoError(t, stream.Feed(wire, emit))
		require.Len(t, observations, 2, "a rekey/replay cannot create another initial observation")
	}
}

func TestInitialHandshakeBytewiseAndCompatibility(t *testing.T) {
	var stream Stream
	wire := append([]byte("SSH-1.99-fixture\n"), testPacket(testKEXPayload(asymmetricLists()))...)
	var observations []Observation
	for _, b := range wire {
		require.NoError(t, stream.Feed([]byte{b}, func(o Observation) { observations = append(observations, o) }))
		require.LessOrEqual(t, stream.BufferedBytes(), MaxPacketBytes+5)
	}
	require.Len(t, observations, 2)
	require.True(t, observations[0].Identification.Supported)
	require.Equal(t, StopKEXComplete, stream.StopReason())
}

func TestInitialHandshakeIncompleteAndEncryptedBoundary(t *testing.T) {
	packet := testPacket(testKEXPayload(asymmetricLists()))
	var stream Stream
	var observations []Observation
	emit := func(o Observation) { observations = append(observations, o) }
	require.NoError(t, stream.Feed([]byte("SSH-2.0-fixture\r\n"), emit))
	require.NoError(t, stream.Feed(packet[:len(packet)-1], emit))
	require.Equal(t, StopIncomplete, stream.End())
	require.Len(t, observations, 1)
	require.NoError(t, stream.Feed(packet, emit))
	require.Len(t, observations, 1)

	stream = Stream{}
	observations = nil
	wire := append([]byte("SSH-2.0-fixture\r\n"), testPacket([]byte{21})...)
	wire = append(wire, packet...)
	require.NoError(t, stream.Feed(wire, emit))
	require.Equal(t, StopNewKeys, stream.End())
	require.Len(t, observations, 1, "bytes after NEWKEYS are never cleartext KEXINIT")
	stream = Stream{}
	require.NoError(t, stream.Feed([]byte("SSH-1.5-fixture\r\n"), nil))
	require.Equal(t, StopUnsupportedVersion, stream.End())
	stream = Stream{}
	require.Equal(t, StopMissingBanner, stream.End())
	stream = Stream{}
	require.NoError(t, stream.Feed([]byte("SSH-2.0-fixture\n"), nil))
	require.Equal(t, StopNoKEX, stream.End())
}

func TestInitialHandshakeDisconnectAndNonUTF8Comments(t *testing.T) {
	var stream Stream
	var observations []Observation
	emit := func(o Observation) { observations = append(observations, o) }
	banner := []byte("SSH-2.0-fixture \xff\r\n")
	wire := append(append([]byte(nil), banner...), testPacket(testKEXPayload(asymmetricLists()))...)
	require.NoError(t, stream.Feed(wire, emit))
	require.Len(t, observations, 2)
	require.Equal(t, "SSH-2.0-fixture \xff", observations[0].Identification.Banner)
	fp, ok := observations[1].KEXINIT.Fingerprint(RoleClient)
	require.True(t, ok)
	require.Equal(t, "cafb69eb1dbb2a4a505b5b25342a4940", fp.Hash)

	stream = Stream{}
	observations = nil
	disconnect := binary.BigEndian.AppendUint32([]byte{1}, 11)
	disconnect = binary.BigEndian.AppendUint32(disconnect, 0) // Empty description.
	disconnect = binary.BigEndian.AppendUint32(disconnect, 0) // Empty language.
	wire = append([]byte("SSH-2.0-fixture\r\n"), testPacket(disconnect)...)
	wire = append(wire, testPacket(testKEXPayload(asymmetricLists()))...)
	require.NoError(t, stream.Feed(wire, emit))
	require.Equal(t, StopDisconnect, stream.End())
	require.Len(t, observations, 1)
	require.Zero(t, stream.BufferedBytes())
}

func TestKEXINITRejectsMalformedAndTruncated(t *testing.T) {
	valid := testKEXPayload(asymmetricLists())
	for end := 0; end < len(valid); end++ {
		_, err := ParseKEXINIT(valid[:end])
		require.Error(t, err)
	}
	for _, change := range []func([]byte){
		func(p []byte) { p[0] = 21 },
		func(p []byte) { binary.BigEndian.PutUint32(p[17:21], ^uint32(0)) },
		func(p []byte) { p[len(p)-1] = 1 },
	} {
		bad := append([]byte(nil), valid...)
		change(bad)
		_, err := ParseKEXINIT(bad)
		require.Error(t, err)
	}
	_, err := ParseKEXINIT(append(valid, 0))
	require.Error(t, err)
	for _, invalid := range []string{"", ",a", "a,", "a,,b", "a b", "a\x00b", "ä", strings.Repeat("a", 65)} {
		lists := asymmetricLists()
		lists[0] = invalid
		_, err = ParseKEXINIT(testKEXPayload(lists))
		require.Error(t, err, "invalid name-list %q", invalid)
	}
}

func TestInitialHandshakeFramingBounds(t *testing.T) {
	for _, header := range [][]byte{
		{0xff, 0xff, 0xff, 0xff, 4}, // No allocation from unchecked wire length.
		{0, 0, 0, 12, 3},            // Padding below four.
		{0, 0, 0, 11, 4},            // Minimum packet and block alignment.
		{0, 0, 0, 12, 11},           // No payload byte.
	} {
		var stream Stream
		require.NoError(t, stream.Feed([]byte("SSH-2.0-fixture\r\n"), nil))
		require.Error(t, stream.Feed(header, nil))
		require.True(t, stream.Stopped())
		require.Zero(t, stream.BufferedBytes())
	}
	var stream Stream
	require.Error(t, stream.Feed([]byte(strings.Repeat("x", MaxIdentificationBytes+1)), nil))
	require.Equal(t, StopResourceLimit, stream.StopReason())
	stream = Stream{}
	require.Error(t, stream.Feed([]byte(strings.Repeat("prelude\n", MaxPreludeLines+1)), nil))
	require.Equal(t, StopResourceLimit, stream.StopReason())
	for _, banner := range []string{"SSH-2.0-\r\n", "SSH-2.0-bad-version\r\n", "SSH-2.0-fixture\x00\r\n", "SSH-2.0-fixture\xff\r\n"} {
		_, err := ParseIdentification([]byte(banner))
		require.Error(t, err)
	}
}

func FuzzInitialHandshake(f *testing.F) {
	f.Add([]byte("SSH-2.0-fixture\r\n"))
	f.Add(append([]byte("SSH-2.0-fixture\r\n"), testPacket(testKEXPayload(asymmetricLists()))...))
	f.Add([]byte{0xff, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		var stream Stream
		err := stream.Feed(data, func(o Observation) {
			if o.KEXINIT != nil {
				_, ok := o.KEXINIT.Fingerprint(RoleUnknown)
				require.False(t, ok)
			}
		})
		if err != nil {
			require.True(t, stream.Stopped(), "malformed input terminates this half-stream")
		}
		require.LessOrEqual(t, stream.BufferedBytes(), MaxPacketBytes+5)
		stream.End()
		require.Zero(t, stream.BufferedBytes())
	})
}
