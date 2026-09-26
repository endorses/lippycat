//go:build li

package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

const journalSequenceReserve int64 = 16 << 10
const maxJournalSequenceIdentityBytes = 512

type journalSequenceEntry struct {
	size int64
	next uint32
}
type sequenceWrite struct {
	key        string
	checkpoint x2x3.SequenceCheckpoint
	data       []byte
	oldSize    int64
}

func sequenceKey(c x2x3.SequenceContext) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func (j *Journal) prepareSequence(data []byte) (*sequenceWrite, error) {
	if !j.cfg.PreserveSequences {
		return nil, nil
	}
	cp, err := x2x3.X2SequenceCheckpoint(data)
	if err != nil {
		return nil, err
	}
	if err := validateSequenceIdentity(cp.Context); err != nil {
		return nil, err
	}
	key, err := sequenceKey(cp.Context)
	if err != nil {
		return nil, err
	}
	j.mu.Lock()
	old, ok := j.sequences[key]
	count := len(j.sequences)
	j.mu.Unlock()
	if ok && int32(cp.Next-old.next) <= 0 {
		return nil, nil
	}
	if !ok && count >= j.cfg.MaxRecords {
		return nil, fmt.Errorf("journal sequence context capacity exhausted")
	}
	plain, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	b, err := j.encodeObject(securestore.SequenceCheckpoint, "sequence/"+key, JournalRecord{Data: plain})
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > journalSequenceReserve {
		return nil, fmt.Errorf("journal sequence identity exceeds 16 KiB")
	}
	return &sequenceWrite{key: key, checkpoint: cp, data: b, oldSize: old.size}, nil
}
func (j *Journal) readSequence(name string) (x2x3.SequenceCheckpoint, error) {
	var cp x2x3.SequenceCheckpoint
	key := strings.TrimSuffix(name, ".seq")
	rawKey, err := hex.DecodeString(key)
	if err != nil || len(rawKey) != sha256.Size || key != strings.ToLower(key) {
		return cp, fmt.Errorf("invalid sequence checkpoint name")
	}
	b, err := j.store.Read(name, journalSequenceReserve)
	if err != nil {
		return cp, err
	}
	r, err := j.decodeObject(securestore.SequenceCheckpoint, "sequence/"+key, b, int(journalSequenceReserve)-1024)
	if err != nil {
		return cp, err
	}
	payload := r.Data
	r.Data = nil
	if r.ID != 0 || !validJournalState(r) {
		return cp, fmt.Errorf("invalid sequence checkpoint wrapper")
	}
	if err := decodeJournalJSON(payload, journalSequenceFields, &cp); err != nil {
		return cp, err
	}
	if cp.Context.PDUType != x2x3.PDUTypeX2 {
		return cp, fmt.Errorf("invalid sequence checkpoint type")
	}
	if err := validateSequenceIdentity(cp.Context); err != nil {
		return cp, err
	}
	actual, err := sequenceKey(cp.Context)
	if err != nil || actual != key {
		return cp, fmt.Errorf("sequence checkpoint identity mismatch")
	}
	return cp, nil
}

func (j *Journal) recoverSequence(name string) error {
	size, err := j.store.AllocatedSize(name)
	if err != nil {
		return err
	}
	if size > j.cfg.MaxBytes-j.faultReserve-j.stats.Bytes {
		return fmt.Errorf("recovered journal exceeds configured capacity: %w", ErrJournalFull)
	}
	cp, err := j.readSequence(name)
	if err != nil {
		return err
	}
	key := strings.TrimSuffix(name, ".seq")
	j.sequences[key] = journalSequenceEntry{size: size, next: cp.Next}
	j.stats.Bytes += size
	return nil
}
func (j *Journal) VisitSequences(visit func(x2x3.SequenceCheckpoint) error) error {
	j.mu.Lock()
	keys := make([]string, 0, len(j.sequences))
	for key := range j.sequences {
		keys = append(keys, key)
	}
	j.mu.Unlock()
	sort.Strings(keys)
	for _, key := range keys {
		cp, err := j.readSequence(key + ".seq")
		if err != nil {
			return err
		}
		if err := visit(cp); err != nil {
			return err
		}
	}
	return nil
}
func validSequenceTemp(name string) bool {
	if !strings.HasSuffix(name, ".seq.tmp") {
		return false
	}
	key := strings.TrimSuffix(name, ".seq.tmp")
	b, err := hex.DecodeString(key)
	return err == nil && len(b) == sha256.Size
}

func validateSequenceIdentity(c x2x3.SequenceContext) error {
	if len(c.DomainID)+len(c.NFID)+len(c.IPID) > maxJournalSequenceIdentityBytes {
		return fmt.Errorf("journal sequence identity exceeds 512 bytes")
	}
	return nil
}
