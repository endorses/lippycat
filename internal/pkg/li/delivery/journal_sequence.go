//go:build li

package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
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
	b, err := j.encode(JournalRecord{Data: plain})
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > journalSequenceReserve {
		return nil, fmt.Errorf("journal sequence identity exceeds 16 KiB")
	}
	return &sequenceWrite{key: key, checkpoint: cp, data: b, oldSize: old.size}, nil
}
func (j *Journal) recoverSequence(name string) error {
	path := filepath.Join(j.cfg.Dir, name)
	if err := checkJournalMode(path, false); err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Size() > journalSequenceReserve {
		return fmt.Errorf("oversized sequence checkpoint")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	r, err := j.decode(b)
	if err != nil {
		return err
	}
	var cp x2x3.SequenceCheckpoint
	if err := json.Unmarshal(r.Data, &cp); err != nil {
		return err
	}
	if cp.Context.PDUType != x2x3.PDUTypeX2 {
		return fmt.Errorf("invalid sequence checkpoint type")
	}
	if err := validateSequenceIdentity(cp.Context); err != nil {
		return err
	}
	key, err := sequenceKey(cp.Context)
	if err != nil {
		return err
	}
	if key+".seq" != name {
		return fmt.Errorf("sequence checkpoint identity mismatch")
	}
	j.sequences[key] = journalSequenceEntry{size: j.diskSize(int64(len(b))), next: cp.Next}
	j.stats.Bytes += j.diskSize(int64(len(b)))
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
		b, err := os.ReadFile(filepath.Join(j.cfg.Dir, key+".seq"))
		if err != nil {
			return err
		}
		r, err := j.decode(b)
		if err != nil {
			return err
		}
		var cp x2x3.SequenceCheckpoint
		if err := json.Unmarshal(r.Data, &cp); err != nil {
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
