// Package packetreceipt defines authenticated, selective raw packet custody
// receipts. A receipt covers durable ingestion, never downstream side effects.
package packetreceipt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

const ProtocolVersion = 1

func ValidIdentity(id *data.RawPacketIdentity) error {
	if id == nil || len(id.ProtoReflect().GetUnknown()) > 0 {
		return errors.New("raw packet identity is required")
	}
	for _, value := range []string{id.SourceId, id.ProducerSessionId, id.CaptureEpoch, id.DestinationId} {
		if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return errors.New("raw packet identity fields must be nonempty bounded identifiers")
		}
	}
	if id.AckScope != "receiver" && id.AckScope != "central" {
		return errors.New("raw receipt scope must be receiver or central")
	}
	return nil
}

func BatchDigest(batch *data.PacketBatch) ([]byte, error) {
	if batch == nil {
		return nil, errors.New("raw packet batch is required")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

type Signer struct {
	authority string
	key       crypto.Signer
}
type Verifier struct {
	authority string
	key       crypto.PublicKey
}

func LoadSigner(authority, certificateFile, keyFile string) (*Signer, error) {
	if authority == "" || len(authority) > 256 || !utf8.ValidString(authority) || strings.ContainsFunc(authority, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, errors.New("receipt authority is required")
	}
	cert, err := securestore.ReadFile(certificateFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read receipt signing certificate: %w", err)
	}
	key, err := securestore.ReadFile(keyFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read receipt signing key: %w", err)
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("load receipt signer: %w", err)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported receipt signing key")
	}
	if err := supportedKey(signer.Public()); err != nil {
		return nil, err
	}
	return &Signer{authority, signer}, nil
}

func LoadVerifier(authority, certificateFile string) (*Verifier, error) {
	encoded, err := securestore.ReadFile(certificateFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read trusted receipt certificate: %w", err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("trusted receipt certificate must be PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse trusted receipt certificate: %w", err)
	}
	if authority == "" || len(authority) > 256 || !utf8.ValidString(authority) || strings.ContainsFunc(authority, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, errors.New("trusted receipt authority is required")
	}
	if err := supportedKey(cert.PublicKey); err != nil {
		return nil, err
	}
	return &Verifier{authority, cert.PublicKey}, nil
}

func supportedKey(key crypto.PublicKey) error {
	switch key := key.(type) {
	case ed25519.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize >= 256 {
			return nil
		}
	case *rsa.PublicKey:
		if key.N.BitLen() >= 2048 {
			return nil
		}
	}
	return errors.New("receipt signing requires Ed25519, ECDSA >=256 bits, or RSA >=2048 bits")
}

func receiptBytes(receipt *data.RawPacketReceipt) ([]byte, error) {
	copy := proto.Clone(receipt).(*data.RawPacketReceipt)
	copy.Signature = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(copy)
	return append([]byte("lippycat/raw-packet-receipt/v1\x00"), encoded...), err
}

func (s *Signer) Sign(receipt *data.RawPacketReceipt) error {
	if s == nil || s.key == nil || receipt == nil || len(receipt.ProtoReflect().GetUnknown()) > 0 || ValidIdentity(receipt.GetIdentity()) != nil {
		return errors.New("valid raw receipt and signing authority are required")
	}
	receipt.ProtocolVersion = ProtocolVersion
	receipt.AuthorityId = s.authority
	encoded, err := receiptBytes(receipt)
	if err != nil {
		return err
	}
	var options crypto.SignerOpts = crypto.SHA256
	digest := sha256.Sum256(encoded)
	message := digest[:]
	if _, ok := s.key.Public().(ed25519.PublicKey); ok {
		options = crypto.Hash(0)
		message = encoded
	}
	receipt.Signature, err = s.key.Sign(rand.Reader, message, options)
	return err
}

// Verify requires the configured end authority even when transport is a relay.
// It never derives trust from the identity named in an incoming receipt.
func (v *Verifier) Verify(receipt *data.RawPacketReceipt, id *data.RawPacketIdentity, batch *data.PacketBatch) error {
	if v == nil || ValidIdentity(id) != nil || receipt == nil || len(receipt.ProtoReflect().GetUnknown()) > 0 || ValidIdentity(receipt.GetIdentity()) != nil || len(receipt.Signature) > 65536 || len(receipt.Losses) > 65536 || receipt.ProtocolVersion != ProtocolVersion || receipt.AuthorityId != v.authority || !proto.Equal(receipt.Identity, id) {
		return errors.New("receipt identity, authority, or version mismatch")
	}
	encoded, err := receiptBytes(receipt)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	valid := false
	switch key := v.key.(type) {
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, encoded, receipt.Signature)
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(key, digest[:], receipt.Signature)
	case *rsa.PublicKey:
		valid = rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], receipt.Signature) == nil
	}
	if !valid {
		return errors.New("raw packet receipt signature rejected")
	}
	if batch != nil {
		if !batchMatches(id, batch) {
			return errors.New("receipt batch identity mismatch")
		}
		hash, err := BatchDigest(batch)
		if err != nil {
			return err
		}
		if receipt.Sequence != batch.Sequence || !bytes.Equal(receipt.ContentSha256, hash) {
			return errors.New("receipt content or sequence mismatch")
		}
	}
	return nil
}
