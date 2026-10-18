package filterpolicy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

const policyIdentityBytes = 56
const maxPolicyEnvelopeBytes = MaxSnapshotBytes + securestore.MaxHeaderBytes + securestore.MaxObjectIDBytes + 18 + 16

type encryptedPolicyState struct {
	keys    *securestore.Keyring
	usage   *securestore.Usage
	writer  *securestore.Writer
	binding securestore.Binding
}

func policyIdentityName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return ".capture-policy-identity-" + hex.EncodeToString(sum[:])
}

// The immutable object binding includes the pinned signer and logical owner,
// independently of the mutable signed policy revision and transport route.
func policyBinding(c Config, verifier *Verifier, name string) ([32]byte, error) {
	pin := sha256.Sum256(verifier.TrustedCertificate().RawSubjectPublicKeyInfo)
	context := struct {
		Version                             int
		Domain, Authority, Owner, Name, Pin string
	}{1, c.Domain, c.AuthorityID, c.Owner, name, hex.EncodeToString(pin[:])}
	encoded, err := json.Marshal(context)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
func policyObject(binding [32]byte) string { return "capture-policy/" + hex.EncodeToString(binding[:]) }

func (s *State) readSnapshot(c Config) ([]byte, error) {
	if c.StorageProtection != "encrypted" {
		return s.dir.Read(s.name, MaxSnapshotBytes)
	}
	ring, err := securestore.LoadKeyring(c.StorageKeys)
	if err != nil {
		return nil, err
	}
	s.encryption = &encryptedPolicyState{keys: ring}
	if s.name == ring.UsageFileName() || policyIdentityName(s.name) == ring.UsageFileName() {
		return nil, fmt.Errorf("policy state collides with encryption usage ledger")
	}
	expected, err := policyBinding(c, s.verifier, s.name)
	if err != nil {
		return nil, err
	}
	identity, err := s.dir.Read(policyIdentityName(s.name), policyIdentityBytes)
	if err != nil {
		return nil, fmt.Errorf("required encrypted capture-policy identity missing or invalid; initialize offline: %w", err)
	}
	if len(identity) != policyIdentityBytes || string(identity[:4]) != "LCPI" || identity[4] != 1 || identity[5] != 0 || identity[6] != 0 || identity[7] != 0 || !bytes.Equal(identity[24:], expected[:]) {
		return nil, securestore.ErrBinding
	}
	var store [16]byte
	copy(store[:], identity[8:24])
	if store == [16]byte{} {
		return nil, securestore.ErrBinding
	}
	usage, err := securestore.OpenUsage(s.dir, ring, store)
	if err != nil {
		return nil, err
	}
	s.encryption.usage = usage
	writer, err := securestore.NewWriter(usage)
	if err != nil {
		return nil, err
	}
	s.encryption.writer = writer
	s.encryption.binding = securestore.Binding{Store: store, Object: policyObject(expected)}
	encoded, err := s.dir.Read(s.name, maxPolicyEnvelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("required encrypted capture-policy snapshot missing or invalid: %w", err)
	}
	return ring.Open(securestore.CapturePolicyState, s.encryption.binding, encoded, MaxSnapshotBytes)
}

func (s *State) writeSnapshot(encoded []byte, snapshot *management.SignedPolicySnapshot) (securestore.Outcome, error) {
	if s.encryption == nil {
		return s.dir.Replace(s.name, encoded)
	}
	var data []byte
	var err error
	if s.emptyWithdrawal(snapshot) {
		data, err = s.encryption.writer.SealControl(securestore.CapturePolicyState, s.encryption.binding, encoded)
	} else {
		data, err = s.encryption.writer.Seal(securestore.CapturePolicyState, s.encryption.binding, encoded)
	}
	if err != nil {
		if errors.Is(err, securestore.ErrUsageFault) {
			s.fault = err
			s.ready = false
		}
		return securestore.NotCommitted, err
	}
	return s.dir.Replace(s.name, data)
}

// Reserve allowance is exclusively for authenticated complete withdrawals of
// previously nonempty policy. Opaque authority bytes cannot be interpreted here,
// so even empty filter lists carrying such authority use ordinary encryption.
func (s *State) emptyWithdrawal(snapshot *management.SignedPolicySnapshot) bool {
	if s.latest == nil || (len(s.latest.Snapshot.Filters) == 0 && len(s.latest.Snapshot.SelectionGrants) == 0) {
		return false
	}
	policy := snapshot.GetSnapshot()
	return policy != nil && len(policy.Filters) == 0 && len(policy.SelectionGrants) == 0 && len(policy.CaptureAuthority) == 0 && !policy.AllowOfflineCapture && len(policy.SourceIds) == 0
}

// Initialize explicitly provisions an encrypted policy store offline. It never
// overwrites existing identity, snapshot or usage-ledger evidence. Partial
// initialization must be reconciled explicitly; neither Initialize nor Open
// recreates missing evidence for a store that may already have used its key.
func Initialize(c Config) (result error) {
	verifier, err := NewVerifier(c)
	if err != nil {
		return err
	}
	c = verifier.config
	if c.StorageProtection != "encrypted" {
		return fmt.Errorf("offline policy initialization requires encrypted storage")
	}
	parent, name := ".", c.StateFile
	if slash := strings.LastIndexByte(c.StateFile, '/'); slash >= 0 {
		parent, name = c.StateFile[:slash], c.StateFile[slash+1:]
		if parent == "" {
			parent = "/"
		}
	}
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid capture-policy state path")
	}
	ring, err := securestore.LoadKeyring(c.StorageKeys)
	if err != nil {
		return err
	}
	identityName := policyIdentityName(name)
	if name == ring.UsageFileName() || identityName == ring.UsageFileName() {
		return fmt.Errorf("policy state collides with encryption usage ledger")
	}
	if err := securestore.EnsureDir(parent); err != nil {
		return err
	}
	dir, err := securestore.OpenDir(parent)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, dir.Close()) }()
	lock, err := dir.Lock(name)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	for _, object := range []string{name, identityName, ring.UsageFileName()} {
		if _, err := dir.FileIdentity(object); err == nil {
			return fmt.Errorf("capture-policy initialization refuses existing store evidence")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	binding, err := policyBinding(c, verifier, name)
	if err != nil {
		return err
	}
	var store [16]byte
	if _, err := rand.Read(store[:]); err != nil {
		return err
	}
	identity := make([]byte, policyIdentityBytes)
	copy(identity, "LCPI")
	identity[4] = 1
	copy(identity[8:24], store[:])
	copy(identity[24:], binding[:])
	if _, err := dir.Create(identityName, identity); err != nil {
		return err
	}
	if _, err := securestore.InitializeUsage(dir, ring, store); err != nil {
		return err
	}
	usage, err := securestore.OpenUsage(dir, ring, store)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, usage.Close()) }()
	writer, err := securestore.NewWriter(usage)
	if err != nil {
		return err
	}
	// The initial empty marker is authenticated but grants no policy/readiness.
	// Initialization always uses ordinary allowance, never the control reserve.
	encoded, err := writer.Seal(securestore.CapturePolicyState, securestore.Binding{Store: store, Object: policyObject(binding)}, nil)
	if err != nil {
		return err
	}
	_, err = dir.Create(name, encoded)
	return err
}
