// Package securestore implements bounded authenticated storage primitives. Store
// owners retain responsibility for schemas, transactions, and authorization.
package securestore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

const (
	KeyBytes      = 32
	MaxKeyIDBytes = 64
	MaxPriorKeys  = 4
)

// KeyRef contains references only. Key files contain exactly 32 raw bytes.
type KeyRef struct{ ID, File string }

type KeyConfig struct {
	Active KeyRef
	Prior  []KeyRef
	// LegacyID explicitly selects the key for formats without an embedded ID.
	// Readers must not try multiple keys until one authenticates.
	LegacyID string
}

type key struct {
	id   string
	raw  [KeyBytes]byte
	aead cipher.AEAD
	file FileIdentity
}

// Keyring is immutable after loading. Never format it in diagnostics.
type Keyring struct {
	active *key
	keys   map[string]*key
	legacy *key
}

func validKeyID(id string) bool {
	if len(id) == 0 || len(id) > MaxKeyIDBytes {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ParseReadKey parses the repeatable id=path configuration surface.
func ParseReadKey(value string) (KeyRef, error) {
	id, path, found := strings.Cut(value, "=")
	if !found || !validKeyID(id) || path == "" {
		return KeyRef{}, errors.New("read key must be id=path with a valid key ID")
	}
	return KeyRef{ID: id, File: path}, nil
}

func LoadKeyring(cfg KeyConfig) (*Keyring, error) {
	if len(cfg.Prior) > MaxPriorKeys {
		return nil, errors.New("at most four prior read keys are supported")
	}
	refs := append([]KeyRef{cfg.Active}, cfg.Prior...)
	r := &Keyring{keys: make(map[string]*key, len(refs))}
	for i, ref := range refs {
		if !validKeyID(ref.ID) || ref.File == "" {
			return nil, errors.New("encrypted storage requires a valid key ID and key file")
		}
		if _, exists := r.keys[ref.ID]; exists {
			return nil, errors.New("duplicate encryption key ID")
		}
		data, identity, err := ReadFileWithIdentity(ref.File, KeyBytes)
		if err != nil {
			return nil, fmt.Errorf("read encryption key: %w", err)
		}
		if len(data) != KeyBytes {
			clear(data)
			return nil, errors.New("encryption key must contain exactly 32 raw bytes")
		}
		k := &key{id: ref.ID, file: identity}
		copy(k.raw[:], data)
		clear(data)
		for _, other := range r.keys {
			if hmac.Equal(k.raw[:], other.raw[:]) {
				return nil, errors.New("key material is duplicated under different IDs")
			}
		}
		block, err := aes.NewCipher(k.raw[:])
		if err != nil {
			return nil, fmt.Errorf("initialize encryption key: %w", err)
		}
		k.aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("initialize authenticated encryption: %w", err)
		}
		r.keys[k.id] = k
		if i == 0 {
			r.active = k
		}
	}
	if cfg.LegacyID != "" {
		r.legacy = r.keys[cfg.LegacyID]
		if r.legacy == nil {
			return nil, errors.New("legacy key ID is not configured")
		}
	}
	return r, nil
}

// CheckIndependent rejects accidental material reuse across enabled stores,
// including prior read keys. It never emits a key ID, path, or fingerprint.
func CheckIndependent(rings ...*Keyring) error {
	for i, a := range rings {
		if a == nil {
			continue
		}
		for _, b := range rings[:i] {
			if b == nil {
				continue
			}
			for _, ak := range a.keys {
				for _, bk := range b.keys {
					if hmac.Equal(ak.raw[:], bk.raw[:]) {
						return errors.New("encrypted stores require independently provisioned keys")
					}
				}
			}
		}
	}
	return nil
}

func (r *Keyring) ActiveID() string { return r.active.id }

// UsageFileName is the reserved active-key accounting object name. It must not
// be reused for a snapshot, key file, manifest, or migration source.
func (r *Keyring) UsageFileName() string { return usageName(r.active) }

// UsesFile compares the actual opened key inodes, including filesystem aliases
// that do not involve symlinks or hardlinks (for example bind mounts).
func (r *Keyring) UsesFile(identity FileIdentity) bool {
	for _, key := range r.keys {
		if key.file == identity {
			return true
		}
	}
	return false
}

// OpenLegacy authenticates a caller-parsed legacy envelope using ONLY the
// explicitly selected legacy key. Legacy format dispatch belongs to its owner.
func (r *Keyring) OpenLegacy(nonce, ciphertext, aad []byte, maxPlaintext int) ([]byte, error) {
	if r.legacy == nil {
		return nil, errors.New("legacy format requires an explicit legacy read-key mapping")
	}
	if maxPlaintext < 0 || maxPlaintext > MaxPlaintextBytes || len(nonce) != nonceBytes || len(ciphertext) < tagBytes || len(ciphertext)-tagBytes > maxPlaintext {
		return nil, ErrEnvelope
	}
	plain, err := r.legacy.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plain, nil
}

func (k *key) mac(label string, data []byte) []byte {
	h := hmac.New(sha256.New, k.raw[:])
	h.Write([]byte(label)) // hash.Hash.Write always returns nil.
	h.Write(data)
	return h.Sum(nil)
}
