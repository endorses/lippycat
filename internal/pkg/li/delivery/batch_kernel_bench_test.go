//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const (
	kernelKeyID       = "kernel"
	kernelMaxFile     = 2 << 20
	kernelMaxPlain    = 1 << 20
	kernelMaxIndex    = 256 << 10
	kernelMaxBatches  = 128
	kernelIndexFixed  = 108
	kernelIndexEntry  = 56
	kernelPrefixBytes = 40
)

// This is deliberately only a durability kernel. Its synthetic owner metadata
// is marked KernelVersion and cannot be mistaken for the production v2 schema.
// It exercises real purpose/binding authentication, usage accounting, immutable
// framing, dependent control/index/sequence evidence and atomic head ordering.
// It does not implement production admission, lifecycle policy, or checkpoints.
type kernelRecord struct {
	KernelVersion uint8     `json:"kernel_version"`
	Journal       uuid.UUID `json:"journal"`
	ID            uint64    `json:"id"`
	XID           uuid.UUID `json:"xid"`
	DID           uuid.UUID `json:"did"`
	SequenceNext  uint32    `json:"sequence_next"`
	OriginalBytes uint32    `json:"original_bytes"`
	PDUHash       string    `json:"pdu_sha256"`
	ControlHash   string    `json:"control_sha256"`
}

var kernelRecordFields = journalJSONFields{"kernel_version": nil, "journal": nil, "id": nil, "xid": nil, "did": nil,
	"sequence_next": nil, "original_bytes": nil, "pdu_sha256": nil, "control_sha256": nil}

type kernelHead struct {
	KernelVersion uint8     `json:"kernel_version"`
	Journal       uuid.UUID `json:"journal"`
	Revision      uint64    `json:"revision"`
	Tip           uuid.UUID `json:"tip"`
	TipHash       string    `json:"tip_sha256"`
	LastID        uint64    `json:"last_id"`
	Call          uuid.UUID `json:"call"`
	ControlOne    string    `json:"control_one_sha256"`
	ControlTwo    string    `json:"control_two_sha256"`
}

var kernelHeadFields = journalJSONFields{"kernel_version": nil, "journal": nil, "revision": nil, "tip": nil,
	"tip_sha256": nil, "last_id": nil, "call": nil, "control_one_sha256": nil, "control_two_sha256": nil}

type batchKernel struct {
	dir     *securestore.Dir
	lock    *securestore.Lock
	keys    *securestore.Keyring
	usage   *securestore.Usage
	writer  *securestore.Writer
	head    kernelHead
	fault   error
	create  func(string, []byte) (securestore.Outcome, error)
	replace func(string, []byte) (securestore.Outcome, error)
	group   func(string, []byte, string, []byte) (securestore.Outcome, error)
}

func newKernelDirectory(parent string) (string, string, error) {
	root, err := os.MkdirTemp(parent, ".li-batch-kernel-")
	if err != nil {
		return "", "", err
	}
	key := make([]byte, 32)
	_, err = rand.Read(key)
	keyFile := filepath.Join(root, "key")
	if err == nil {
		err = os.WriteFile(keyFile, key, 0600)
	}
	clear(key)
	if err == nil {
		err = os.Mkdir(filepath.Join(root, "journal"), 0700)
	}
	if err != nil {
		return "", "", errors.Join(err, os.RemoveAll(root))
	}
	return root, keyFile, nil
}

func openBatchKernel(dir, keyFile string, initialize bool) (_ *batchKernel, resultErr error) {
	k := &batchKernel{}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, k.close())
		}
	}()
	var err error
	k.dir, err = securestore.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	k.lock, err = k.dir.Lock(".head")
	if err != nil {
		return nil, err
	}
	k.keys, err = securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: kernelKeyID, File: keyFile}})
	if err != nil {
		return nil, err
	}
	if initialize {
		k.head.Journal, err = uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		out, err := securestore.InitializeUsage(k.dir, k.keys, [16]byte(k.head.Journal))
		if err != nil || out != securestore.Committed {
			return nil, errors.Join(err, errors.New("kernel usage initialization not committed"))
		}
	}
	k.usage, err = securestore.OpenUsage(k.dir, k.keys, [16]byte{})
	if err != nil {
		return nil, err
	}
	k.writer, err = securestore.NewWriter(k.usage)
	if err != nil {
		return nil, err
	}
	k.create, k.replace = k.dir.Create, k.dir.Replace
	if initialize {
		k.head.KernelVersion = 1
		k.head.Call, err = uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		for destination := range calibrationDIDs {
			// Fixed synthetic dependency, not an implementation of call policy.
			plain := []byte("kernel-only synthetic durable call-open dependency")
			encoded, err := k.writer.SealControl(securestore.CallControl, k.controlBinding(destination), plain)
			if err != nil {
				return nil, err
			}
			out, err := k.create(fmt.Sprintf("control-%d", destination), encoded)
			if err != nil || out != securestore.Committed {
				return nil, errors.Join(err, errors.New("kernel control initialization not committed"))
			}
			digest := kernelDigest(encoded)
			if destination == 0 {
				k.head.ControlOne = digest
			} else {
				k.head.ControlTwo = digest
			}
		}
		encoded, err := k.encodeHead(k.head)
		if err != nil {
			return nil, err
		}
		out, err := k.create(".head", encoded)
		if err != nil || out != securestore.Committed {
			return nil, errors.Join(err, errors.New("kernel head initialization not committed"))
		}
	} else if err := k.recover(); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *batchKernel) close() error {
	var err error
	if k.usage != nil {
		err = errors.Join(err, k.usage.Close())
	}
	if k.lock != nil {
		err = errors.Join(err, k.lock.Close())
	}
	if k.dir != nil {
		err = errors.Join(err, k.dir.Close())
	}
	return err
}

func (k *batchKernel) binding(object string) securestore.Binding {
	return securestore.Binding{Store: k.usage.StoreID(), Object: object}
}

func (k *batchKernel) controlBinding(destination int) securestore.Binding {
	return k.binding(fmt.Sprintf("call/%s/%s/1/%s/1", k.head.Call, calibrationXID, calibrationDIDs[destination]))
}

func kernelDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func kernelName(id uuid.UUID) string { return "batch-" + hex.EncodeToString(id[:]) + ".lcb" }

func (k *batchKernel) encodeHead(head kernelHead) ([]byte, error) {
	plain, err := json.Marshal(head)
	if err != nil {
		return nil, err
	}
	// A head which introduces new product must use ordinary usage allowance.
	return k.writer.Seal(securestore.JournalState, k.binding("journal-state"), plain)
}

// This exact length follows the frozen LCS1 framing; assert it after sealing.
func kernelEnvelopeLength(object string, payload int) int {
	return 20 + len(kernelKeyID) + 12 + 18 + len(object) + payload + 16
}

func (k *batchKernel) encodeBatch(pdus [][]byte) (uuid.UUID, []byte, error) {
	if len(pdus) == 0 || len(pdus) > 4095 || k.head.Revision >= kernelMaxBatches || uint64(len(pdus)) > ^uint64(0)-k.head.LastID {
		return uuid.Nil, nil, errors.New("kernel bounded batch or identity limit")
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return id, nil, err
	}
	var frames, metadata [][]byte
	indexLength, dataLength, totalPlain := kernelIndexFixed, 0, 0
	for i, data := range pdus {
		var pdu x2x3.PDU
		if err := pdu.UnmarshalBinary(data); err != nil || pdu.Header.Type != x2x3.PDUTypeX3 || pdu.Header.XID != calibrationXID {
			return id, nil, errors.New("kernel requires synthetic X3 encoded products")
		}
		var next uint32
		found := false
		for _, attribute := range pdu.Attributes {
			if attribute.Type == x2x3.AttrSequenceNumber {
				if found || len(attribute.Value) != 4 {
					return id, nil, errors.New("kernel duplicate or malformed sequence evidence")
				}
				next, found = binary.BigEndian.Uint32(attribute.Value)+1, true
			}
		}
		if !found {
			return id, nil, errors.New("kernel sequence evidence missing")
		}
		destination := i % 2
		controlHash := k.head.ControlOne
		if destination == 1 {
			controlHash = k.head.ControlTwo
		}
		record := kernelRecord{1, k.head.Journal, k.head.LastID + uint64(i) + 1, calibrationXID, calibrationDIDs[destination], next,
			uint32(len(data)), kernelDigest(data), controlHash}
		meta, err := json.Marshal(record)
		if err != nil {
			return id, nil, err
		}
		plain := make([]byte, 12+len(meta)+len(data))
		copy(plain, "LRB2")
		binary.BigEndian.PutUint32(plain[4:8], uint32(len(meta)))
		binary.BigEndian.PutUint32(plain[8:12], uint32(len(data)))
		copy(plain[12:], meta)
		copy(plain[12+len(meta):], data)
		object := fmt.Sprintf("%d", record.ID)
		totalPlain += 18 + len(object) + len(plain)
		indexLength += kernelIndexEntry + len(meta)
		if totalPlain+indexLength+18+len("batch/")+36 > kernelMaxPlain || indexLength+18+len("batch/")+36 > kernelMaxIndex {
			return id, nil, errors.New("kernel plaintext bound")
		}
		encoded, err := k.writer.Seal(securestore.X3Product, k.binding(object), plain)
		if err != nil {
			return id, nil, err
		}
		frames, metadata = append(frames, encoded), append(metadata, meta)
		dataLength += 4 + len(encoded)
	}
	object := "batch/" + id.String()
	indexEnvelopeLength := kernelEnvelopeLength(object, indexLength)
	fileLength := kernelPrefixBytes + indexEnvelopeLength + dataLength
	if fileLength > kernelMaxFile {
		return id, nil, errors.New("kernel ciphertext bound")
	}
	prefix := make([]byte, kernelPrefixBytes)
	copy(prefix, "LCB1")
	prefix[4], prefix[5] = 1, 2
	copy(prefix[8:24], id[:])
	binary.BigEndian.PutUint32(prefix[24:28], uint32(len(frames)+1))
	binary.BigEndian.PutUint32(prefix[28:32], uint32(indexEnvelopeLength))
	binary.BigEndian.PutUint64(prefix[32:40], uint64(fileLength))
	index := make([]byte, indexLength)
	copy(index, prefix)
	copy(index[40:56], k.head.Tip[:])
	if k.head.Revision != 0 {
		digest, err := hex.DecodeString(k.head.TipHash)
		if err != nil || len(digest) != 32 {
			return id, nil, errors.New("kernel previous tip hash")
		}
		copy(index[56:88], digest)
	}
	binary.BigEndian.PutUint64(index[88:96], k.head.Revision+1)
	binary.BigEndian.PutUint64(index[96:104], k.head.LastID)
	binary.BigEndian.PutUint32(index[104:108], uint32(len(frames)))
	indexOffset, fileOffset := kernelIndexFixed, kernelPrefixBytes+indexEnvelopeLength
	for i, frame := range frames {
		binary.BigEndian.PutUint64(index[indexOffset:indexOffset+8], k.head.LastID+uint64(i)+1)
		binary.BigEndian.PutUint64(index[indexOffset+8:indexOffset+16], uint64(fileOffset))
		binary.BigEndian.PutUint32(index[indexOffset+16:indexOffset+20], uint32(len(frame)))
		digest := sha256.Sum256(frame)
		copy(index[indexOffset+20:indexOffset+52], digest[:])
		binary.BigEndian.PutUint32(index[indexOffset+52:indexOffset+56], uint32(len(metadata[i])))
		copy(index[indexOffset+56:], metadata[i])
		indexOffset += kernelIndexEntry + len(metadata[i])
		fileOffset += 4 + len(frame)
	}
	sealedIndex, err := k.writer.Seal(securestore.JournalBatchIndex, k.binding(object), index)
	if err != nil {
		return id, nil, err
	}
	if len(sealedIndex) != indexEnvelopeLength {
		return id, nil, errors.New("kernel LCS1 framing length mismatch")
	}
	container := make([]byte, 0, fileLength)
	container = append(container, prefix...)
	container = append(container, sealedIndex...)
	for _, frame := range frames {
		container = binary.BigEndian.AppendUint32(container, uint32(len(frame)))
		container = append(container, frame...)
	}
	return id, container, nil
}

func (k *batchKernel) commit(pdus [][]byte, callback func(securestore.Outcome, error)) (out securestore.Outcome, resultErr error) {
	out = securestore.NotCommitted
	defer func() {
		if resultErr != nil {
			resultErr = &securestore.CommitError{Outcome: out, Op: "kernel batch and head", Err: resultErr}
			k.fault = resultErr
		}
		for range pdus {
			callback(out, resultErr)
		}
	}()
	if k.fault != nil {
		return out, k.fault
	}
	id, encoded, err := k.encodeBatch(pdus)
	if err != nil {
		return out, err
	}
	if k.group == nil {
		batchOutcome, err := k.create(kernelName(id), encoded)
		if err != nil || batchOutcome != securestore.Committed {
			return out, errors.Join(err, &securestore.CommitError{Outcome: batchOutcome, Op: "kernel prerequisite batch", Err: errors.New("batch prerequisite publication failed")})
		}
	}
	head := k.head
	head.Revision++
	head.Tip, head.TipHash, head.LastID = id, kernelDigest(encoded), head.LastID+uint64(len(pdus))
	headData, err := k.encodeHead(head)
	if err != nil {
		return out, err
	}
	if k.group == nil {
		out, err = k.replace(".head", headData)
	} else {
		out, err = k.group(kernelName(id), encoded, ".head", headData)
	}
	if out == securestore.Committed {
		k.head = head
	}
	if err == nil && out != securestore.Committed {
		err = errors.New("kernel head not definitely committed")
	}
	return out, err
}

func (k *batchKernel) recover() error {
	encoded, err := k.dir.Read(".head", 64<<10)
	if err != nil {
		return err
	}
	plain, err := k.keys.Open(securestore.JournalState, k.binding("journal-state"), encoded, 64<<10-1024)
	if err != nil {
		return err
	}
	if err := decodeJournalJSON(plain, kernelHeadFields, &k.head); err != nil {
		return err
	}
	if k.head.KernelVersion != 1 || [16]byte(k.head.Journal) != k.usage.StoreID() || k.head.Call == uuid.Nil || k.head.Revision > kernelMaxBatches {
		return errors.New("kernel head identity or bound")
	}
	for destination, expected := range []string{k.head.ControlOne, k.head.ControlTwo} {
		data, err := k.dir.Read(fmt.Sprintf("control-%d", destination), 4096)
		if err != nil || kernelDigest(data) != expected {
			return errors.New("kernel dependent control missing or corrupt")
		}
		if _, err := k.keys.Open(securestore.CallControl, k.controlBinding(destination), data, 1024); err != nil {
			return err
		}
	}
	tip, digest, revision, lastID := k.head.Tip, k.head.TipHash, k.head.Revision, k.head.LastID
	seen := make(map[string]bool)
	for revision > 0 {
		name := kernelName(tip)
		if tip == uuid.Nil || seen[name] {
			return errors.New("kernel missing or cyclic batch identity")
		}
		seen[name] = true
		data, err := k.dir.Read(name, kernelMaxFile)
		if err != nil || kernelDigest(data) != digest {
			return errors.New("kernel committed batch missing or corrupt")
		}
		tip, digest, lastID, err = k.readBatch(tip, revision, lastID, data)
		if err != nil {
			return err
		}
		revision--
	}
	if tip != uuid.Nil || digest != "" || lastID != 0 {
		return errors.New("kernel transaction chain does not reach initialized root")
	}
	return k.dir.WalkEntries(func(name string) error {
		switch {
		case name == ".head" || name == "control-0" || name == "control-1":
			return nil
		case strings.HasPrefix(name, "batch-"):
			if !seen[name] {
				return errors.New("kernel complete unreferenced batch requires reconciliation")
			}
			return nil
		default:
			_, err := k.dir.MetadataAllocatedSize(name)
			return err
		}
	})
}

func (k *batchKernel) readBatch(id uuid.UUID, revision, lastID uint64, data []byte) (uuid.UUID, string, uint64, error) {
	fail := func() (uuid.UUID, string, uint64, error) {
		return uuid.Nil, "", 0, errors.New("kernel authenticated framing or metadata invalid")
	}
	if len(data) < kernelPrefixBytes || len(data) > kernelMaxFile || string(data[:4]) != "LCB1" || data[4] != 1 || data[5] != 2 || data[6] != 0 || data[7] != 0 || !bytes.Equal(data[8:24], id[:]) || binary.BigEndian.Uint64(data[32:40]) != uint64(len(data)) {
		return fail()
	}
	frames, indexLen := binary.BigEndian.Uint32(data[24:28]), binary.BigEndian.Uint32(data[28:32])
	if frames < 2 || frames > 4096 || indexLen > kernelMaxIndex+securestore.MaxHeaderBytes+16 || uint64(indexLen) > uint64(len(data)-kernelPrefixBytes) {
		return fail()
	}
	indexObject := "batch/" + id.String()
	index, err := k.keys.Open(securestore.JournalBatchIndex, k.binding(indexObject), data[40:40+int(indexLen)], kernelMaxIndex-18-len(indexObject))
	if err != nil || len(index) < kernelIndexFixed || !bytes.Equal(index[:40], data[:40]) || binary.BigEndian.Uint64(index[88:96]) != revision || binary.BigEndian.Uint32(index[104:108]) != frames-1 {
		return fail()
	}
	previousLastID := binary.BigEndian.Uint64(index[96:104])
	if lastID < previousLastID || lastID-previousLastID != uint64(frames-1) {
		return fail()
	}
	indexOffset, offset := kernelIndexFixed, 40+int(indexLen)
	totalPlain := 18 + len(indexObject) + len(index)
	for i := uint32(0); i < frames-1; i++ {
		if len(index)-indexOffset < kernelIndexEntry || len(data)-offset < 4 {
			return fail()
		}
		entry := index[indexOffset : indexOffset+kernelIndexEntry]
		recordID, frameOffset, frameLen, metadataLen := binary.BigEndian.Uint64(entry[:8]), binary.BigEndian.Uint64(entry[8:16]), binary.BigEndian.Uint32(entry[16:20]), binary.BigEndian.Uint32(entry[52:56])
		if recordID != previousLastID+uint64(i)+1 || frameOffset != uint64(offset) || frameLen != binary.BigEndian.Uint32(data[offset:offset+4]) || uint64(frameLen) > uint64(len(data)-offset-4) || metadataLen > 64<<10 || uint64(metadataLen) > uint64(len(index)-indexOffset-kernelIndexEntry) {
			return fail()
		}
		frame := data[offset+4 : offset+4+int(frameLen)]
		hash := sha256.Sum256(frame)
		if !bytes.Equal(hash[:], entry[20:52]) {
			return fail()
		}
		meta := index[indexOffset+kernelIndexEntry : indexOffset+kernelIndexEntry+int(metadataLen)]
		var record kernelRecord
		if err := decodeJournalJSON(meta, kernelRecordFields, &record); err != nil || record.KernelVersion != 1 || record.Journal != k.head.Journal || record.ID != recordID || record.XID != calibrationXID || record.DID != calibrationDIDs[i%2] {
			return fail()
		}
		controlHash := k.head.ControlOne
		if i%2 == 1 {
			controlHash = k.head.ControlTwo
		}
		if record.ControlHash != controlHash {
			return fail()
		}
		object := fmt.Sprintf("%d", recordID)
		if int(metadataLen)+18+len(object) > 64<<10 {
			return fail()
		}
		plain, err := k.keys.Open(securestore.X3Product, k.binding(object), frame, kernelMaxPlain-18-len(object))
		if err != nil || len(plain) < 12 || string(plain[:4]) != "LRB2" || binary.BigEndian.Uint32(plain[4:8]) != metadataLen || uint64(metadataLen) > uint64(len(plain)-12) || binary.BigEndian.Uint32(plain[8:12]) != record.OriginalBytes || uint64(record.OriginalBytes) != uint64(len(plain)-12)-uint64(metadataLen) || !bytes.Equal(plain[12:12+int(metadataLen)], meta) {
			return fail()
		}
		totalPlain += 18 + len(object) + len(plain)
		if totalPlain > kernelMaxPlain {
			return fail()
		}
		pduBytes := plain[12+int(metadataLen):]
		var pdu x2x3.PDU
		if kernelDigest(pduBytes) != record.PDUHash || pdu.UnmarshalBinary(pduBytes) != nil || pdu.Header.Type != x2x3.PDUTypeX3 || pdu.Header.XID != record.XID {
			return fail()
		}
		sequenceCount := 0
		for _, attribute := range pdu.Attributes {
			if attribute.Type == x2x3.AttrSequenceNumber {
				if len(attribute.Value) != 4 || binary.BigEndian.Uint32(attribute.Value)+1 != record.SequenceNext {
					return fail()
				}
				sequenceCount++
			}
		}
		if sequenceCount != 1 {
			return fail()
		}
		indexOffset += kernelIndexEntry + int(metadataLen)
		offset += 4 + int(frameLen)
	}
	if indexOffset != len(index) || offset != len(data) {
		return fail()
	}
	var previous uuid.UUID
	copy(previous[:], index[40:56])
	previousHash := hex.EncodeToString(index[56:88])
	if previous == uuid.Nil {
		if !bytes.Equal(index[56:88], make([]byte, 32)) {
			return fail()
		}
		previousHash = ""
	}
	return previous, previousHash, previousLastID, nil
}

func kernelProducts(count int, ordinal uint64) ([][]byte, error) {
	pdus := make([][]byte, count)
	for i := range pdus {
		data, _, _, err := calibrationProduct(ordinal+uint64(i/2), max(1, count/2), true)
		if err != nil {
			return nil, err
		}
		pdus[i] = data
	}
	return pdus, nil
}

func TestBatchKernelCommitOutcomesAndRecovery(t *testing.T) {
	injected := errors.New("synthetic boundary failure")
	for _, stage := range []string{"success", "batch-not-committed", "batch-uncertain", "head-not-committed", "head-uncertain", "head-committed-cleanup"} {
		t.Run(stage, func(t *testing.T) {
			root, key, err := newKernelDirectory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.RemoveAll(root); err != nil {
					t.Error(err)
				}
			}()
			dir := filepath.Join(root, "journal")
			k, err := openBatchKernel(dir, key, true)
			if err != nil {
				t.Fatal(err)
			}
			pdus, err := kernelProducts(2, 0)
			if err != nil {
				t.Fatal(err)
			}
			create, replace := k.create, k.replace
			callbacks, successes := 0, 0
			k.create = func(name string, data []byte) (securestore.Outcome, error) {
				if stage == "batch-not-committed" {
					return securestore.NotCommitted, injected
				}
				out, err := create(name, data)
				if err == nil && stage == "batch-uncertain" {
					return securestore.Uncertain, injected
				}
				return out, err
			}
			k.replace = func(name string, data []byte) (securestore.Outcome, error) {
				if callbacks != 0 {
					t.Fatal("callback occurred before head publication")
				}
				if stage == "head-not-committed" {
					return securestore.NotCommitted, injected
				}
				out, err := replace(name, data)
				if err == nil && stage == "head-uncertain" {
					return securestore.Uncertain, injected
				}
				if err == nil && stage == "head-committed-cleanup" {
					return securestore.Committed, injected
				}
				return out, err
			}
			var callbackOut securestore.Outcome
			out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
				callbacks++
				callbackOut = out
				if err == nil {
					successes++
				}
			})
			want := securestore.NotCommitted
			if stage == "success" || stage == "head-committed-cleanup" {
				want = securestore.Committed
			}
			if stage == "head-uncertain" {
				want = securestore.Uncertain
			}
			if callbacks != 2 || out != want || callbackOut != want || (stage == "success") != (err == nil) || (stage == "success" && successes != 2) || (stage != "success" && successes != 0) {
				t.Fatalf("boundary %s: callbacks=%d successes=%d outcome=%v err=%v", stage, callbacks, successes, out, err)
			}
			if err != nil && securestore.OutcomeOf(err) != want {
				t.Fatal("outer outcome lost")
			}
			if err := k.close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openBatchKernel(dir, key, false)
			orphan := stage == "batch-uncertain" || stage == "head-not-committed"
			if orphan {
				if err == nil {
					if closeErr := reopened.close(); closeErr != nil {
						t.Error(closeErr)
					}
					t.Fatal("complete orphan must stop recovery")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := reopened.close(); err != nil {
					t.Error(err)
				}
			}()
			wantRevision := uint64(1)
			if stage == "batch-not-committed" {
				wantRevision = 0
			}
			if reopened.head.Revision != wantRevision {
				t.Fatal("wrong recovered authority")
			}
		})
	}
}

func TestBatchKernelRejectsCommittedCorruptionAndBounds(t *testing.T) {
	root, key, err := newKernelDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	}()
	dir := filepath.Join(root, "journal")
	k, err := openBatchKernel(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	pdus, err := kernelProducts(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.encodeBatch(make([][]byte, 4096)); err == nil {
		t.Fatal("frame bound ignored")
	}
	id, encoded, err := k.encodeBatch(pdus)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := k.readBatch(id, 1, 2, encoded); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 4, 5, 6, 8, 24, 28, 32, 40, len(encoded) - 1} {
		changed := bytes.Clone(encoded)
		changed[offset] ^= 1
		if _, _, _, err := k.readBatch(id, 1, 2, changed); err == nil {
			t.Fatalf("accepted changed byte %d", offset)
		}
	}
	for _, n := range []int{0, 39, 40, len(encoded) - 1} {
		if _, _, _, err := k.readBatch(id, 1, 2, encoded[:n]); err == nil {
			t.Fatalf("accepted truncated batch %d", n)
		}
	}
	// Authenticate malformed indexes so bounds are tested beyond the outer AEAD
	// check. Also reauthenticate a changed frame digest to reach product AEAD.
	indexLen := int(binary.BigEndian.Uint32(encoded[28:32]))
	indexObject := "batch/" + id.String()
	indexPlain, err := k.keys.Open(securestore.JournalBatchIndex, k.binding(indexObject), encoded[40:40+indexLen], kernelMaxIndex-18-len(indexObject))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"offset-overflow", "length-overflow", "metadata-overflow", "duplicate-id", "wrong-revision", "changed-product"} {
		index := bytes.Clone(indexPlain)
		changed := bytes.Clone(encoded)
		switch mutation {
		case "offset-overflow":
			binary.BigEndian.PutUint64(index[kernelIndexFixed+8:kernelIndexFixed+16], ^uint64(0))
		case "length-overflow":
			binary.BigEndian.PutUint32(index[kernelIndexFixed+16:kernelIndexFixed+20], ^uint32(0))
		case "metadata-overflow":
			binary.BigEndian.PutUint32(index[kernelIndexFixed+52:kernelIndexFixed+56], ^uint32(0))
		case "duplicate-id":
			binary.BigEndian.PutUint64(index[kernelIndexFixed:kernelIndexFixed+8], 2)
		case "wrong-revision":
			binary.BigEndian.PutUint64(index[88:96], 2)
		case "changed-product":
			frameOffset := 40 + indexLen
			frameLen := int(binary.BigEndian.Uint32(changed[frameOffset : frameOffset+4]))
			frame := changed[frameOffset+4 : frameOffset+4+frameLen]
			frame[len(frame)-1] ^= 1
			digest := sha256.Sum256(frame)
			copy(index[kernelIndexFixed+20:kernelIndexFixed+52], digest[:])
		}
		sealed, err := k.writer.Seal(securestore.JournalBatchIndex, k.binding(indexObject), index)
		if err != nil || len(sealed) != indexLen {
			t.Fatalf("reseal authenticated mutation: %v", err)
		}
		copy(changed[40:40+indexLen], sealed)
		if _, _, _, err := k.readBatch(id, 1, 2, changed); err == nil {
			t.Fatalf("accepted authenticated mutation %s", mutation)
		}
	}
	if _, err := k.commit(pdus, func(securestore.Outcome, error) {}); err != nil {
		t.Fatal(err)
	}
	name := kernelName(k.head.Tip)
	committed, err := k.dir.Read(name, kernelMaxFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.close(); err != nil {
		t.Fatal(err)
	}
	committed[len(committed)-1] ^= 1
	if err := os.WriteFile(filepath.Join(dir, name), committed, 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := openBatchKernel(dir, key, false); err == nil {
		if closeErr := reopened.close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("committed corruption discarded")
	}
}

func BenchmarkBatchHeadDurabilityKernel(b *testing.B) {
	benchmarkBatchHeadKernel(b, false)
}

func BenchmarkGroupedBatchHeadDurabilityKernel(b *testing.B) {
	benchmarkBatchHeadKernel(b, true)
}

func benchmarkBatchHeadKernel(b *testing.B, grouped bool) {
	parent := os.Getenv("LC_LI_STORAGE_BENCH_DIR")
	if parent == "" {
		b.Skip("set LC_LI_STORAGE_BENCH_DIR for opt-in durable kernel measurement")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(parent, &fs); err != nil {
		b.Fatal(err)
	}
	if fs.Type == 0x01021994 || fs.Type == 0x858458f6 || fs.Bavail*uint64(fs.Bsize) < 1<<30 {
		b.Fatal("kernel requires durable filesystem and 1 GiB free")
	}
	for _, count := range []int{2, 200} {
		b.Run(fmt.Sprintf("records=%d", count), func(b *testing.B) {
			if b.N != 1 {
				b.Fatal("use -benchtime=1x")
			}
			root, key, err := newKernelDirectory(parent)
			if err != nil {
				b.Fatal(err)
			}
			defer func() {
				if err := os.RemoveAll(root); err != nil {
					b.Error(err)
				}
			}()
			dir := filepath.Join(root, "journal")
			k, err := openBatchKernel(dir, key, true)
			if err != nil {
				b.Fatal(err)
			}
			defer func() {
				if k != nil {
					if err := k.close(); err != nil {
						b.Error(err)
					}
				}
			}()
			var latency, durable, batchIO, headIO, groupIO calibrationHistogram
			create, replace := k.create, k.replace
			k.create = func(name string, data []byte) (securestore.Outcome, error) {
				start := time.Now()
				out, err := create(name, data)
				batchIO.add(time.Since(start))
				return out, err
			}
			k.replace = func(name string, data []byte) (securestore.Outcome, error) {
				start := time.Now()
				out, err := replace(name, data)
				headIO.add(time.Since(start))
				return out, err
			}
			if grouped {
				k.group = func(name string, data []byte, head string, headData []byte) (securestore.Outcome, error) {
					start := time.Now()
					out, err := k.dir.CreateAndReplace(name, data, head, headData)
					groupIO.add(time.Since(start))
					return out, err
				}
			}
			usageBefore := k.usage.Stats()
			const batches = 40
			const accumulation = 10 * time.Millisecond
			// This fixed-size probe retains at most 8,000 durations (64 KiB) so
			// threshold decisions do not depend on histogram bucket rounding.
			exactCallbacks := make([]time.Duration, 0, batches*count)
			var callbacks int
			started := time.Now()
			for batch := 0; batch < batches; batch++ {
				pdus, err := kernelProducts(count, uint64(batch*count/2))
				if err != nil {
					b.Fatal(err)
				}
				firstArrival := time.Now()
				time.Sleep(accumulation)
				commitStart := time.Now()
				within := 0
				out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
					if out != securestore.Committed || err != nil {
						b.Errorf("kernel callback outcome %v: %v", out, err)
						return
					}
					// Uniform synthetic arrivals through the measured 10 ms window.
					arrived := firstArrival.Add(time.Duration(within) * accumulation / time.Duration(count))
					elapsed := time.Since(arrived)
					latency.add(elapsed)
					exactCallbacks = append(exactCallbacks, elapsed)
					within++
					callbacks++
				})
				durable.add(time.Since(commitStart))
				if err != nil || out != securestore.Committed {
					b.Fatalf("kernel commit %v: %v", out, err)
				}
			}
			wall := time.Since(started).Seconds()
			usageAfter := k.usage.Stats()
			allocated, _, err := calibrationAllocated(dir)
			if err != nil {
				b.Fatal(err)
			}
			if err := k.close(); err != nil {
				b.Fatal(err)
			}
			k = nil
			recoveryStart := time.Now()
			reopened, err := openBatchKernel(dir, key, false)
			if err != nil {
				b.Fatal(err)
			}
			recovery := time.Since(recoveryStart).Seconds()
			if reopened.head.Revision != batches || reopened.head.LastID != uint64(batches*count) {
				b.Fatal("kernel recovered wrong highwater")
			}
			if err := reopened.close(); err != nil {
				b.Fatal(err)
			}
			slices.Sort(exactCallbacks)
			exactPercentile := func(percent int) float64 {
				return float64(exactCallbacks[(len(exactCallbacks)*percent+99)/100-1]) / float64(time.Millisecond)
			}
			result := struct {
				GroupedPublication                                                         bool
				Records, Batches, Callbacks                                                int
				WallSeconds, CopiesPerSecond, RecoverySeconds                              float64
				AllocatedBytes                                                             int64
				Callback, CommitIncludingUsageAndCrypto, BatchPublication, HeadPublication calibrationLatency
				GroupedIO                                                                  calibrationLatency
				CallbackP50ExactMS, CallbackP99ExactMS                                     float64
				UsageBefore, UsageAfter                                                    securestore.UsageStats
			}{grouped, count, batches, callbacks, wall, float64(callbacks) / wall, recovery, allocated, latency.summary(), durable.summary(), batchIO.summary(), headIO.summary(), groupIO.summary(), exactPercentile(50), exactPercentile(99), usageBefore, usageAfter}
			data, err := json.Marshal(result)
			if err != nil {
				b.Fatal(err)
			}
			b.Logf("BATCH_HEAD_KERNEL %s", data)
			b.ReportMetric(latency.quantile(50), "callback-p50-ms-upper")
			b.ReportMetric(latency.quantile(99), "callback-p99-ms-upper")
			b.ReportMetric(exactPercentile(50), "callback-p50-ms-exact")
		})
	}
}

func TestBatchKernelGroupedOutcomeAndMissingPrerequisite(t *testing.T) {
	for _, scenario := range []string{"committed", "not-committed-orphan", "uncertain", "committed-cleanup"} {
		t.Run(scenario, func(t *testing.T) {
			root, key, err := newKernelDirectory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.RemoveAll(root); err != nil {
					t.Error(err)
				}
			}()
			dir := filepath.Join(root, "journal")
			k, err := openBatchKernel(dir, key, true)
			if err != nil {
				t.Fatal(err)
			}
			pdus, err := kernelProducts(2, 0)
			if err != nil {
				t.Fatal(err)
			}
			// First establish an older valid transaction: recovery must never
			// fall back to it if the later selected batch is absent or corrupt.
			k.group = k.dir.CreateAndReplace
			if _, err := k.commit(pdus, func(securestore.Outcome, error) {}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("synthetic grouped owner fault")
			k.group = func(name string, data []byte, head string, headData []byte) (securestore.Outcome, error) {
				if scenario == "not-committed-orphan" {
					if _, err := k.dir.Create(name, data); err != nil {
						return securestore.NotCommitted, err
					}
					return securestore.NotCommitted, injected
				}
				out, err := k.dir.CreateAndReplace(name, data, head, headData)
				if err == nil && scenario == "uncertain" {
					return securestore.Uncertain, injected
				}
				if err == nil && scenario == "committed-cleanup" {
					return securestore.Committed, injected
				}
				return out, err
			}
			callbacks, successes := 0, 0
			want := securestore.Committed
			if scenario == "not-committed-orphan" {
				want = securestore.NotCommitted
			}
			if scenario == "uncertain" {
				want = securestore.Uncertain
			}
			out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
				callbacks++
				if out != want {
					t.Errorf("wrong callback outcome %v", out)
				}
				if err == nil {
					successes++
				}
			})
			if callbacks != 2 || out != want || (scenario == "committed") != (err == nil) || (scenario != "committed" && successes != 0) {
				t.Fatalf("grouped callback/outcome mismatch: %d/%d %v %v", callbacks, successes, out, err)
			}
			if err != nil {
				k.group = func(string, []byte, string, []byte) (securestore.Outcome, error) {
					t.Fatal("faulted owner published again")
					return securestore.NotCommitted, nil
				}
				if _, err := k.commit(pdus, func(securestore.Outcome, error) {}); err == nil {
					t.Fatal("faulted owner accepted mutation")
				}
			}
			if err := k.close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openBatchKernel(dir, key, false)
			if scenario == "not-committed-orphan" {
				if err == nil {
					if err := reopened.close(); err != nil {
						t.Error(err)
					}
					t.Fatal("orphan silently removed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if reopened.head.Revision != 2 {
				t.Fatal("recovery fell back to older head")
			}
			selected := kernelName(reopened.head.Tip)
			if err := reopened.close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, selected)); err != nil {
				t.Fatal(err)
			}
			if reopened, err := openBatchKernel(dir, key, false); err == nil {
				if err := reopened.close(); err != nil {
					t.Error(err)
				}
				t.Fatal("missing selected batch permitted fallback to older transaction")
			}
		})
	}
}
