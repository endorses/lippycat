//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const rewriteMetadataBytes int64 = 1 << 20

var errRewrite = errors.New("invalid or mismatched offline journal rewrite")

type journalRewriteRequest struct {
	Version                                 int
	SourceDirectory, DestinationDirectory   string
	SourcePath, DestinationPath, SourceRing [32]byte
	Source                                  JournalRewriteMetadata
	OutputUUID                              uuid.UUID
	SourceKeyID, NewKeyID                   string
	InPlace                                 bool
	MaxBytes, MaxWorkingBytes               int64
	Plan                                    JournalRewritePlan
}

type journalRewriteSlot struct {
	ID       uuid.UUID
	Kind     string
	Identity securestore.FileIdentity
}

type journalRewriteProgress struct {
	Version         int
	Request         journalRewriteRequest
	Phase           string
	Attempt         uint64
	Slots           []journalRewriteSlot
	CandidateBytes  int64
	CandidateSHA256 [32]byte
}

// Only random identity, bounded resource counts and opaque commitments are
// cleartext. The complete request and all operation state remain encrypted.
type journalRewriteBootstrap struct {
	Stage          byte
	Store          uuid.UUID
	Token          [32]byte
	Data, Controls uint16
}

func rewriteRequestToken(r journalRewriteRequest, key *securestore.Keyring) ([32]byte, error) {
	b, err := json.Marshal(r)
	if err != nil || len(b) > securestore.MaxInitializationContextBytes-32 {
		return [32]byte{}, errRewrite
	}
	return key.InitializationBinding(securestore.JournalState, append([]byte("journal-rewrite/request/v1\x00"), b...))
}

func (b journalRewriteBootstrap) encode(key *securestore.Keyring) ([]byte, error) {
	if b.Stage < 1 || b.Stage > 2 || b.Store == uuid.Nil || b.Token == [32]byte{} || b.Data == 0 || b.Controls == 0 || int(b.Data)+int(b.Controls) > journalSegmentMax {
		return nil, errRewrite
	}
	raw := make([]byte, 92)
	copy(raw, "LCJR")
	raw[4], raw[5] = 1, b.Stage
	copy(raw[8:24], b.Store[:])
	copy(raw[24:56], b.Token[:])
	binary.BigEndian.PutUint16(raw[56:58], b.Data)
	binary.BigEndian.PutUint16(raw[58:60], b.Controls)
	mac, err := key.InitializationBinding(securestore.JournalState, append([]byte("journal-rewrite/bootstrap/v1\x00"), raw[:60]...))
	if err != nil {
		return nil, err
	}
	copy(raw[60:], mac[:])
	return raw, nil
}

func decodeRewriteBootstrap(raw []byte, key *securestore.Keyring) (journalRewriteBootstrap, error) {
	var b journalRewriteBootstrap
	if len(raw) != 92 || string(raw[:4]) != "LCJR" || raw[4] != 1 || raw[6] != 0 || raw[7] != 0 {
		return b, errRewrite
	}
	b.Stage = raw[5]
	copy(b.Store[:], raw[8:24])
	copy(b.Token[:], raw[24:56])
	b.Data = binary.BigEndian.Uint16(raw[56:58])
	b.Controls = binary.BigEndian.Uint16(raw[58:60])
	expected, err := b.encode(key)
	if err != nil || !hmac.Equal(raw, expected) {
		return journalRewriteBootstrap{}, errRewrite
	}
	return b, nil
}

func rewriteNames() (bootstrap, progress, candidate string) {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:.segments", securestore.JournalState)))
	base := hex.EncodeToString(sum[:])
	return ".rotation-bootstrap-" + base, ".rotation-progress-" + base, ".rotation-candidate-" + base
}

func rewriteArchive(token [32]byte) string {
	return ".rotation-source-catalog-" + hex.EncodeToString(token[:])
}
func rewriteProgressObject(token [32]byte) string {
	return "journal-rewrite/progress/" + hex.EncodeToString(token[:])
}
func rewriteLockName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return ".securestore-lock-" + hex.EncodeToString(sum[:])
}
func rewriteSlotID(token [32]byte, attempt uint64, index int) uuid.UUID {
	b := append([]byte("journal-rewrite/segment/v1\x00"), token[:]...)
	b = binary.BigEndian.AppendUint64(b, attempt)
	b = binary.BigEndian.AppendUint32(b, uint32(index))
	return uuid.NewSHA1(uuid.NameSpaceOID, b)
}

func (r *journalRewriteOperation) decodeProgress(raw []byte) (*journalRewriteProgress, error) {
	return decodeRewriteProgress(raw, r.newKeys, r.boot)
}
func decodeRewriteProgress(raw []byte, ring *securestore.Keyring, boot journalRewriteBootstrap) (*journalRewriteProgress, error) {
	plain, err := ring.Open(securestore.JournalState, securestore.Binding{Store: [16]byte(boot.Store), Object: rewriteProgressObject(boot.Token)}, raw, int(rewriteMetadataBytes))
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var p journalRewriteProgress
	if err := strictSegmentJSON(plain, &p); err != nil {
		return nil, err
	}
	if p.Version != 1 || p.Attempt == 0 || p.Attempt == ^uint64(0) || len(p.Slots) != int(boot.Data)+int(boot.Controls) || (p.Phase != "planned" && p.Phase != "prepared" && p.Phase != "complete") {
		return nil, errRewrite
	}
	token, err := rewriteRequestToken(p.Request, ring)
	if err != nil || token != boot.Token || p.Request.OutputUUID != boot.Store || p.Request.Plan.DataSegments != int(boot.Data) || p.Request.Plan.ControlSegments != int(boot.Controls) {
		return nil, errRewrite
	}
	for i, slot := range p.Slots {
		kind := "data"
		if i >= int(boot.Data) {
			kind = "control"
		}
		if slot.ID != rewriteSlotID(token, p.Attempt, i) || slot.Kind != kind || slot.Identity.Inode == 0 {
			return nil, errRewrite
		}
	}
	if p.Phase == "planned" {
		if p.CandidateBytes != 0 || p.CandidateSHA256 != [32]byte{} {
			return nil, errRewrite
		}
	} else if p.CandidateBytes <= 0 || p.CandidateBytes > rewriteMetadataBytes || p.CandidateSHA256 == [32]byte{} {
		return nil, errRewrite
	}
	return &p, nil
}

func sameRewriteRequest(a, b journalRewriteRequest) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func completedRewriteReceipt(bootstrap, progress []byte, ring *securestore.Keyring) error {
	b, err := decodeRewriteBootstrap(bootstrap, ring)
	if err != nil {
		return err
	}
	p, err := decodeRewriteProgress(progress, ring, b)
	if err != nil {
		return err
	}
	if b.Stage != 2 || p.Phase != "complete" {
		return errors.New("source has an unfinished journal rewrite")
	}
	return nil
}

func (r *journalRewriteOperation) loadLineage(bootstrap []byte) error {
	raw, err := r.destinationDir.Read(r.progressName, rewriteMetadataBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, openErr := decodeRewriteBootstrap(bootstrap, r.newKeys)
	if openErr != nil {
		if !r.options.InPlace {
			return openErr
		}
		if err := completedRewriteReceipt(bootstrap, raw, r.sourceKeys); err != nil {
			return err
		}
		r.predecessorBootstrap, r.predecessorProgress = bootstrap, raw
		r.fresh = true
		return nil
	}
	if !r.options.Resume {
		return errors.New("journal rewrite already exists; explicit resume required")
	}
	r.boot = b
	// A replacement bootstrap can precede its first encrypted plan. The exact
	// completed predecessor is archived before that bootstrap publication.
	base := hex.EncodeToString(b.Token[:])
	priorBoot, e := r.destinationDir.Read(".rotation-prev-bootstrap-"+base, 92)
	if e == nil {
		priorProgress, e := r.destinationDir.Read(".rotation-prev-progress-"+base, rewriteMetadataBytes)
		if e != nil {
			return e
		}
		if err := completedRewriteReceipt(priorBoot, priorProgress, r.sourceKeys); err != nil {
			return err
		}
		r.predecessorBootstrap, r.predecessorProgress = priorBoot, priorProgress
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if raw == nil || bytes.Equal(raw, r.predecessorProgress) {
		return nil
	}
	r.progress, err = r.decodeProgress(raw)
	return err
}

func (r *journalRewriteOperation) validateSourceLineage() error {
	b, err := r.sourceDir.Read(r.bootstrapName, 92)
	if errors.Is(err, os.ErrNotExist) {
		if _, e := r.sourceDir.FileIdentity(r.progressName); e == nil {
			return errRewrite
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return nil
	}
	if err != nil {
		return err
	}
	p, err := r.sourceDir.Read(r.progressName, rewriteMetadataBytes)
	if err != nil {
		return err
	}
	return completedRewriteReceipt(b, p, r.sourceKeys)
}
