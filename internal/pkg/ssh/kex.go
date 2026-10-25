// Package ssh parses the visible initial SSH transport handshake. It does not
// decrypt SSH, identify authenticated users, or inspect encrypted rekey traffic.
package ssh

import (
	"crypto/md5" // HASSH specifies MD5; this is a fingerprint, not authentication.
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// MaxPacketBytes supports RFC 4253 section 6.1's required initial packet size.
// Larger optional SSH packets are outside this parser's supported bounds.
const MaxPacketBytes = 35000

type Role string

const (
	RoleUnknown Role = "unknown"
	RoleClient  Role = "client"
	RoleServer  Role = "server"
)

// KEXINIT owns the exact received, ordered algorithm lists. No list is sorted,
// deduplicated, case folded, or stripped of extension-negotiation markers.
type KEXINIT struct {
	KEXAlgorithms           string
	ServerHostKeyAlgorithms string
	EncryptionClientServer  string
	EncryptionServerClient  string
	MACClientServer         string
	MACServerClient         string
	CompressionClientServer string
	CompressionServerClient string
	LanguagesClientServer   string
	LanguagesServerClient   string
	FirstKEXPacketFollows   bool
}

// ParseKEXINIT consumes one complete uncompressed SSH_MSG_KEXINIT payload,
// including message byte 20 and excluding binary framing and padding. Lengths
// are checked before conversion/allocation. See RFC 4253 section 7.1 and
// https://www.rfc-editor.org/rfc/rfc4251.html#section-6 for name bounds.
func ParseKEXINIT(payload []byte) (*KEXINIT, error) {
	if len(payload) < 62 || len(payload) > MaxPacketBytes || payload[0] != 20 {
		return nil, errors.New("invalid SSH KEXINIT payload size or message")
	}
	var lists [10]string
	offset := 17 // Message byte and random cookie; cookie is not a HASSH input.
	for i := range lists {
		if len(payload)-offset < 4 {
			return nil, errors.New("truncated SSH KEXINIT name-list length")
		}
		n := uint64(binary.BigEndian.Uint32(payload[offset : offset+4]))
		offset += 4
		if n > uint64(len(payload)-offset) {
			return nil, errors.New("truncated SSH KEXINIT name-list")
		}
		value := payload[offset : offset+int(n)]
		if !validNameList(value, i >= 8) {
			return nil, fmt.Errorf("invalid SSH KEXINIT name-list %d", i)
		}
		lists[i] = string(value)
		offset += int(n)
	}
	if len(payload)-offset != 5 || binary.BigEndian.Uint32(payload[offset+1:]) != 0 {
		return nil, errors.New("invalid SSH KEXINIT reserved word or trailing data")
	}
	return &KEXINIT{
		KEXAlgorithms: lists[0], ServerHostKeyAlgorithms: lists[1],
		EncryptionClientServer: lists[2], EncryptionServerClient: lists[3],
		MACClientServer: lists[4], MACServerClient: lists[5],
		CompressionClientServer: lists[6], CompressionServerClient: lists[7],
		LanguagesClientServer: lists[8], LanguagesServerClient: lists[9],
		// RFC 4251 section 5 requires readers to interpret any nonzero byte
		// as true, even though senders must encode true as one.
		FirstKEXPacketFollows: payload[offset] != 0,
	}, nil
}

func validNameList(value []byte, language bool) bool {
	if len(value) == 0 {
		return language
	}
	nameBytes := 0
	for _, b := range value {
		if b == ',' {
			if nameBytes == 0 {
				return false
			}
			nameBytes = 0
			continue
		}
		// The 64-byte identifier limit applies to algorithms, not language
		// tags. Both remain bounded by the entire admitted KEXINIT payload.
		if b <= 32 || b >= 127 || (!language && nameBytes >= 64) {
			return false
		}
		nameBytes++
	}
	return nameBytes != 0
}

type Fingerprint struct {
	Version    string
	Hash       string
	Algorithms string
}

// Fingerprint implements the HASSH 1.0 client/server definitions maintained at
// https://github.com/corelight/hassh/blob/main/scripts/hassh.zeek . Endpoint role
// must come from independent evidence; first-seen TCP direction is insufficient.
// Unknown roles and incomplete/invalid KEXINIT values never produce a hash.
func (k *KEXINIT) Fingerprint(role Role) (Fingerprint, bool) {
	if k == nil || (role != RoleClient && role != RoleServer) {
		return Fingerprint{}, false
	}
	lists := []string{k.KEXAlgorithms, k.ServerHostKeyAlgorithms,
		k.EncryptionClientServer, k.EncryptionServerClient, k.MACClientServer,
		k.MACServerClient, k.CompressionClientServer, k.CompressionServerClient,
		k.LanguagesClientServer, k.LanguagesServerClient}
	var bytes int
	for i, value := range lists {
		if len(value) > MaxPacketBytes || !validNameList([]byte(value), i >= 8) {
			return Fingerprint{}, false
		}
		bytes += len(value)
	}
	if bytes > MaxPacketBytes-62 {
		return Fingerprint{}, false
	}
	enc, mac, compression := k.EncryptionClientServer, k.MACClientServer, k.CompressionClientServer
	if role == RoleServer {
		enc, mac, compression = k.EncryptionServerClient, k.MACServerClient, k.CompressionServerClient
	}
	algorithms := strings.Join([]string{k.KEXAlgorithms, enc, mac, compression}, ";")
	digest := md5.Sum([]byte(algorithms))
	return Fingerprint{Version: "1.0", Hash: hex.EncodeToString(digest[:]), Algorithms: algorithms}, true
}
