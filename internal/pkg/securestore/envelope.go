package securestore

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	MaxPlaintextBytes = 64 << 20
	MaxObjectIDBytes  = 512
	MaxHeaderBytes    = 96
	MaxEnvelopeBytes  = MaxHeaderBytes + MaxPlaintextBytes + tagBytes
	fixedHeaderBytes  = 20
	nonceBytes        = 12
	tagBytes          = 16
	bindingFixedBytes = 18
)

var (
	ErrEnvelope       = errors.New("invalid encrypted envelope")
	ErrAuthentication = errors.New("encrypted storage authentication failed")
	ErrBinding        = errors.New("encrypted storage identity mismatch")
)

type Purpose uint16

const (
	FilterSnapshot Purpose = iota + 1
	AdministrativeState
	X2Product
	X3Product
	SequenceCheckpoint
	JournalState
	CallControl
	RevocationControl
)

func (p Purpose) valid() bool { return p >= FilterSnapshot && p <= RevocationControl }
func (p Purpose) control() bool {
	return p.valid() && p != X2Product && p != X3Product
}

// Binding is authenticated inside the ciphertext. Store comes from the locked,
// authenticated store identity, never from the object being checked.
type Binding struct {
	Store  [16]byte
	Object string
}

func (b Binding) valid() bool {
	return b.Store != [16]byte{} && len(b.Object) > 0 && len(b.Object) <= MaxObjectIDBytes && utf8.ValidString(b.Object) && !strings.ContainsRune(b.Object, 0)
}

// Writer cannot seal without a durable invocation reservation. The usage ledger
// owns the active key; readers need only the Keyring.
type Writer struct{ usage *Usage }

func NewWriter(usage *Usage) (*Writer, error) {
	if usage == nil {
		return nil, errors.New("encrypted writer requires a usage ledger")
	}
	return &Writer{usage: usage}, nil
}

func (w *Writer) Seal(p Purpose, b Binding, data []byte) ([]byte, error) {
	return w.seal(p, b, data, false)
}

// SealControl uses the reserved final allowance for controls and snapshots that
// withdraw enforcement or finish already accepted transactions. Owners must
// enforce that classification and reserve disk capacity before accepting product.
func (w *Writer) SealControl(p Purpose, b Binding, data []byte) ([]byte, error) {
	if !p.control() {
		return nil, errors.New("product writes cannot use control encryption allowance")
	}
	return w.seal(p, b, data, true)
}

func (w *Writer) seal(p Purpose, b Binding, data []byte, control bool) ([]byte, error) {
	if !p.valid() || !b.valid() || b.Store != w.usage.StoreID() || len(data) > MaxPlaintextBytes-bindingFixedBytes-len(b.Object) {
		return nil, ErrEnvelope
	}
	k := w.usage.key
	headerLen := fixedHeaderBytes + len(k.id) + nonceBytes
	plainLen := bindingFixedBytes + len(b.Object) + len(data)
	// Charge all authenticated/ciphertext blocks and the GCM length block.
	blocks := uint64((headerLen+15)/16 + (plainLen+tagBytes+15)/16 + 1)
	if err := w.usage.reserve(blocks, control); err != nil {
		return nil, &CommitError{Outcome: NotCommitted, Op: "encrypt object", Err: err}
	}
	header := make([]byte, headerLen)
	copy(header, "LCS1")
	header[4], header[5] = 1, 1 // envelope version and AES-256-GCM algorithm
	binary.BigEndian.PutUint16(header[6:8], uint16(p))
	binary.BigEndian.PutUint16(header[8:10], uint16(len(k.id)))
	binary.BigEndian.PutUint16(header[10:12], nonceBytes)
	binary.BigEndian.PutUint64(header[12:20], uint64(plainLen+tagBytes))
	copy(header[20:], k.id)
	nonce := header[headerLen-nonceBytes:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	plain := make([]byte, plainLen)
	copy(plain, b.Store[:])
	binary.BigEndian.PutUint16(plain[16:18], uint16(len(b.Object)))
	copy(plain[18:], b.Object)
	copy(plain[18+len(b.Object):], data)
	defer clear(plain)
	// Allocate a distinct destination so AAD and append capacity never overlap.
	out := make([]byte, headerLen, headerLen+plainLen+tagBytes)
	copy(out, header)
	return k.aead.Seal(out, nonce, plain, header), nil
}

// Open validates framing and expected bounds before decrypting. Errors never
// include ciphertext, plaintext, sensitive object identities, or keys.
func (r *Keyring) Open(p Purpose, b Binding, data []byte, maxPayload int) ([]byte, error) {
	if !p.valid() || !b.valid() || maxPayload < 0 || maxPayload > MaxPlaintextBytes-bindingFixedBytes-len(b.Object) {
		return nil, ErrEnvelope
	}
	if len(data) < fixedHeaderBytes || len(data) > MaxEnvelopeBytes || !bytes.Equal(data[:4], []byte("LCS1")) || data[4] != 1 || data[5] != 1 {
		return nil, ErrEnvelope
	}
	if Purpose(binary.BigEndian.Uint16(data[6:8])) != p || binary.BigEndian.Uint16(data[10:12]) != nonceBytes {
		return nil, ErrEnvelope
	}
	idLen := int(binary.BigEndian.Uint16(data[8:10]))
	if idLen < 1 || idLen > MaxKeyIDBytes {
		return nil, ErrEnvelope
	}
	headerLen := fixedHeaderBytes + idLen + nonceBytes
	if len(data) < headerLen+tagBytes {
		return nil, ErrEnvelope
	}
	cipherLen := binary.BigEndian.Uint64(data[12:20])
	if cipherLen != uint64(len(data)-headerLen) || cipherLen < tagBytes+bindingFixedBytes+1 || cipherLen > uint64(tagBytes+bindingFixedBytes+len(b.Object)+maxPayload) {
		return nil, ErrEnvelope
	}
	id := string(data[20 : 20+idLen])
	if !validKeyID(id) {
		return nil, ErrEnvelope
	}
	k := r.keys[id]
	if k == nil {
		return nil, ErrAuthentication
	}
	plain, err := k.aead.Open(nil, data[headerLen-nonceBytes:headerLen], data[headerLen:], data[:headerLen])
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(plain) < bindingFixedBytes {
		clear(plain)
		return nil, ErrEnvelope
	}
	objectLen := int(binary.BigEndian.Uint16(plain[16:18]))
	if objectLen != len(b.Object) || len(plain) < bindingFixedBytes+objectLen || !bytes.Equal(plain[:16], b.Store[:]) || string(plain[18:18+objectLen]) != b.Object {
		clear(plain)
		return nil, ErrBinding
	}
	return plain[bindingFixedBytes+objectLen:], nil
}
