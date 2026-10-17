package filterpolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

const MaxSnapshotBytes = constants.MaxGRPCMessageSize
const maxSnapshotFilters = 65536

var ErrInvalid = errors.New("invalid or unauthenticated shared policy")
var ErrRollback = errors.New("shared policy rollback or conflicting revision")

type Verifier struct {
	config      Config
	certificate *x509.Certificate
}

func NewVerifier(config Config) (*Verifier, error) {
	c, err := Normalize(config)
	if err != nil {
		return nil, err
	}
	if c.Mode != "shared" {
		return nil, fmt.Errorf("shared policy verifier requires shared mode")
	}
	encoded, err := os.ReadFile(c.TrustedCertFile)
	if err != nil {
		return nil, fmt.Errorf("read policy trust certificate: %w", err)
	}
	if len(encoded) > 1<<20 {
		return nil, fmt.Errorf("policy trust certificate is oversized")
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("policy trust requires exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse policy trust certificate: %w", err)
	}
	if time.Now().Before(certificate.NotBefore) || time.Now().After(certificate.NotAfter) {
		return nil, fmt.Errorf("policy trust certificate is outside its validity interval")
	}
	switch key := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return nil, fmt.Errorf("policy ECDSA key is too small")
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return nil, fmt.Errorf("policy RSA key is too small")
		}
	default:
		return nil, fmt.Errorf("unsupported policy signing key")
	}
	return &Verifier{config: c, certificate: certificate}, nil
}

func (v *Verifier) TrustedCertificate() *x509.Certificate { return v.certificate }

func validateSnapshot(s *management.PolicySnapshot, c Config) error {
	if s == nil || s.ProtocolVersion != 1 || s.Domain != c.Domain || s.AuthorityId != c.AuthorityID || s.Revision == 0 || len(s.Filters) > maxSnapshotFilters || proto.Size(s) > MaxSnapshotBytes || len(s.ProtoReflect().GetUnknown()) != 0 {
		return ErrInvalid
	}
	owner := s.GetOwnerKind()
	if owner == "" {
		owner = "shared"
	}
	if owner != c.Owner {
		return ErrInvalid
	}
	if owner == "shared" && (len(s.CaptureAuthority) > 0 || s.ValidFromNs != 0 || s.ValidUntilNs != 0 || s.AllowOfflineCapture || len(s.SourceIds) > 0) {
		return ErrInvalid
	}
	if owner == "li" && ((s.ValidFromNs < 0 || s.ValidUntilNs < 0) || (s.ValidUntilNs != 0 && s.ValidUntilNs <= s.ValidFromNs)) {
		return ErrInvalid
	}
	prefix := c.Namespace()
	previous := ""
	for _, f := range s.Filters {
		if f == nil || !strings.HasPrefix(f.Id, prefix) || len(f.Id) == len(prefix) || len(f.Id) > 1024 || f.Id <= previous || len(f.ProtoReflect().GetUnknown()) != 0 {
			return ErrInvalid
		}
		if err := filtercodec.ValidateManagedFilter(f); err != nil {
			return ErrInvalid
		}
		previous = f.Id
	}
	return nil
}

func signatureInput(s *management.PolicySnapshot) ([]byte, error) {
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(s)
	if err != nil {
		return nil, err
	}
	return append([]byte("lippycat/shared-filter-policy/v1\x00"), b...), nil
}
func (v *Verifier) Verify(signed *management.SignedPolicySnapshot) error {
	if time.Now().Before(v.certificate.NotBefore) || time.Now().After(v.certificate.NotAfter) {
		return ErrInvalid
	}
	if signed == nil || len(signed.Signature) == 0 || len(signed.Signature) > 16384 || len(signed.ProtoReflect().GetUnknown()) != 0 || proto.Size(signed) > MaxSnapshotBytes {
		return ErrInvalid
	}
	if err := validateSnapshot(signed.Snapshot, v.config); err != nil {
		return err
	}
	input, err := signatureInput(signed.Snapshot)
	if err != nil {
		return ErrInvalid
	}
	algorithm := x509.PureEd25519
	switch v.certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		algorithm = x509.ECDSAWithSHA256
	case *rsa.PublicKey:
		algorithm = x509.SHA256WithRSA
	}
	if err := v.certificate.CheckSignature(algorithm, input, signed.Signature); err != nil {
		return ErrInvalid
	}
	return nil
}

func (v *Verifier) ReadSigner(path string) (crypto.Signer, error) {
	source, err := securestore.OpenPrivateSource(path)
	if err != nil {
		return nil, fmt.Errorf("open private policy signing key: %w", err)
	}
	encoded, readErr := source.Read(1 << 20)
	closeErr := source.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("invalid policy signing key PEM")
	}
	defer clear(block.Bytes)
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unsupported policy private key encoding")
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("policy private key cannot sign")
	}
	if !PublicKeysEqual(signer.Public(), v.certificate.PublicKey) {
		return nil, fmt.Errorf("policy signing key does not match trusted authority")
	}
	return signer, nil
}

func PublicKeysEqual(a, b crypto.PublicKey) bool {
	aa, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bb, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return sha256.Sum256(aa) == sha256.Sum256(bb)
}
func (v *Verifier) Sign(signer crypto.Signer, revision uint64, filters []*management.Filter) (*management.SignedPolicySnapshot, error) {
	snapshot := &management.PolicySnapshot{ProtocolVersion: 1, Domain: v.config.Domain, AuthorityId: v.config.AuthorityID, Revision: revision, OwnerKind: v.config.Owner}
	for _, filter := range filters {
		if filter == nil {
			return nil, ErrInvalid
		}
		snapshot.Filters = append(snapshot.Filters, proto.Clone(filter).(*management.Filter))
	}
	return v.SignSnapshot(signer, snapshot)
}

// SignSnapshot signs explicitly supplied owner metadata without changing filter
// identifiers. Generic shared snapshots cannot carry LI authorization fields.
func (v *Verifier) SignSnapshot(signer crypto.Signer, inputSnapshot *management.PolicySnapshot) (*management.SignedPolicySnapshot, error) {
	if inputSnapshot == nil {
		return nil, ErrInvalid
	}
	snapshot := proto.Clone(inputSnapshot).(*management.PolicySnapshot)
	sort.Slice(snapshot.Filters, func(i, j int) bool { return snapshot.Filters[i].Id < snapshot.Filters[j].Id })
	if err := validateSnapshot(snapshot, v.config); err != nil {
		return nil, err
	}
	input, err := signatureInput(snapshot)
	if err != nil {
		return nil, err
	}
	var digest []byte
	var opts crypto.SignerOpts = crypto.SHA256
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		digest = input
		opts = crypto.Hash(0)
	} else {
		sum := sha256.Sum256(input)
		digest = sum[:]
	}
	signature, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}
	signed := &management.SignedPolicySnapshot{Snapshot: snapshot, Signature: signature}
	if err := v.Verify(signed); err != nil {
		return nil, err
	}
	return signed, nil
}
