//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const (
	containerPrefixBytes  = 48
	containerHeadBytes    = 248
	containerMaxBytes     = 2097591
	containerDiskBudget   = 96 << 20
	containerScratchBytes = 16 << 20
)

type kernelContainer struct {
	ID, Previous            uuid.UUID
	PreviousHash, BatchHash [32]byte
	Head                    kernelHead
}

type containerKernel struct {
	*batchKernel
	selected     kernelContainer
	selectedHash [32]byte
	publish      func(string, string, string, []byte) (securestore.Outcome, error)
	retained     int64
}

type containerStageError struct{ kind string }

func (e *containerStageError) Error() string {
	return "kernel container staging requires offline reconciliation: " + e.kind
}

func containerArchive(id uuid.UUID) string { return "head-" + hex.EncodeToString(id[:]) + ".lhc" }
func containerStage(id uuid.UUID) string   { return ".lch-stage-" + hex.EncodeToString(id[:]) + ".tmp" }
func containerNameID(name, prefix, suffix string) (uuid.UUID, bool) {
	if len(name) != len(prefix)+32+len(suffix) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return uuid.Nil, false
	}
	raw := name[len(prefix) : len(prefix)+32]
	decoded, err := hex.DecodeString(raw)
	if err != nil || raw != strings.ToLower(raw) {
		return uuid.Nil, false
	}
	var id uuid.UUID
	copy(id[:], decoded)
	return id, id != uuid.Nil
}

func openContainerKernel(dir, keyFile string, initialize bool) (_ *containerKernel, resultErr error) {
	k := &containerKernel{batchKernel: &batchKernel{}}
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
	if initialize {
		// Only the caller-created empty disposable directory may initialize a root.
		if err := k.dir.WalkEntries(func(string) error { return errors.New("kernel initialization requires empty directory") }); err != nil {
			return nil, err
		}
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
			return nil, errors.Join(err, errors.New("kernel usage initialization failed"))
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
	k.publish = k.dir.ExchangeAndArchive
	if initialize {
		k.head.KernelVersion = 1
		k.head.Call, err = uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		for destination := range calibrationDIDs {
			data, err := k.writer.SealControl(securestore.CallControl, k.controlBinding(destination), []byte("kernel-only synthetic durable call-open dependency"))
			if err != nil {
				return nil, err
			}
			out, err := k.dir.Create(fmt.Sprintf("control-%d", destination), data)
			if err != nil || out != securestore.Committed {
				return nil, errors.Join(err, errors.New("kernel control initialization failed"))
			}
			if destination == 0 {
				k.head.ControlOne = kernelDigest(data)
			} else {
				k.head.ControlTwo = kernelDigest(data)
			}
		}
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		root := kernelContainer{ID: id, Head: k.head, BatchHash: sha256.Sum256(nil)}
		data, err := k.encodeContainer(root, nil)
		if err != nil {
			return nil, err
		}
		out, err := k.publish(containerStage(id), ".head", "", data)
		if err != nil || out != securestore.Committed {
			return nil, errors.Join(err, errors.New("kernel root initialization failed"))
		}
		k.selected, k.selectedHash = root, sha256.Sum256(data)
	} else if err := k.recoverContainers(); err != nil {
		return nil, err
	}
	k.retained, err = k.allocated()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (k *containerKernel) encodeContainer(c kernelContainer, batch []byte) ([]byte, error) {
	if len(batch) > kernelMaxFile {
		return nil, errors.New("kernel container batch bound")
	}
	headLength := 327 + len(kernelKeyID)
	prefix := make([]byte, containerPrefixBytes)
	copy(prefix, "LCH1")
	prefix[4], prefix[5] = 1, 2
	if len(batch) > 0 {
		prefix[6] = 1
	}
	copy(prefix[8:24], c.ID[:])
	binary.BigEndian.PutUint32(prefix[24:28], uint32(len(batch)))
	binary.BigEndian.PutUint32(prefix[28:32], uint32(headLength))
	binary.BigEndian.PutUint64(prefix[32:40], uint64(containerPrefixBytes+len(batch)+headLength))
	plain := make([]byte, containerHeadBytes)
	copy(plain, "LHK1")
	binary.BigEndian.PutUint16(plain[4:6], 1)
	copy(plain[8:56], prefix)
	copy(plain[56:72], c.Head.Journal[:])
	binary.BigEndian.PutUint64(plain[72:80], c.Head.Revision)
	copy(plain[80:96], c.Previous[:])
	copy(plain[96:128], c.PreviousHash[:])
	copy(plain[128:160], c.BatchHash[:])
	binary.BigEndian.PutUint64(plain[160:168], c.Head.LastID)
	copy(plain[168:184], c.Head.Call[:])
	for i, digest := range []string{c.Head.ControlOne, c.Head.ControlTwo} {
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("kernel control digest invalid")
		}
		copy(plain[184+i*32:216+i*32], raw)
	}
	sealed, err := k.writer.Seal(securestore.JournalState, k.binding("journal-state"), plain)
	if err != nil {
		return nil, err
	}
	if len(sealed) != headLength {
		return nil, errors.New("kernel fixed head envelope length mismatch")
	}
	encoded := make([]byte, 0, containerPrefixBytes+len(batch)+len(sealed))
	encoded = append(encoded, prefix...)
	encoded = append(encoded, batch...)
	encoded = append(encoded, sealed...)
	return encoded, nil
}

func (k *containerKernel) decodeContainer(data []byte) (kernelContainer, []byte, error) {
	fail := func() (kernelContainer, []byte, error) {
		return kernelContainer{}, nil, errors.New("kernel authenticated container framing invalid")
	}
	if len(data) < containerPrefixBytes || len(data) > containerMaxBytes || string(data[:4]) != "LCH1" || data[4] != 1 || data[5] != 2 || data[6] > 1 || data[7] != 0 || !bytes.Equal(data[40:48], make([]byte, 8)) {
		return fail()
	}
	n := binary.BigEndian.Uint32(data[24:28])
	h := binary.BigEndian.Uint32(data[28:32])
	if n > kernelMaxFile || uint64(n) > uint64(len(data)-containerPrefixBytes) || h < 328 || h > 391 || uint64(h) != uint64(len(data)-containerPrefixBytes)-uint64(n) || binary.BigEndian.Uint64(data[32:40]) != uint64(len(data)) {
		return fail()
	}
	batch := data[48 : 48+int(n)]
	sealed := data[48+int(n):]
	if len(sealed) < 20 || int(h) != 327+int(binary.BigEndian.Uint16(sealed[8:10])) {
		return fail()
	}
	plain, err := k.keys.Open(securestore.JournalState, k.binding("journal-state"), sealed, containerHeadBytes)
	storeID := k.usage.StoreID()
	if err != nil || len(plain) != containerHeadBytes || string(plain[:4]) != "LHK1" || binary.BigEndian.Uint16(plain[4:6]) != 1 || plain[6] != 0 || plain[7] != 0 || !bytes.Equal(plain[8:56], data[:48]) || !bytes.Equal(plain[56:72], storeID[:]) {
		return fail()
	}
	var c kernelContainer
	copy(c.ID[:], data[8:24])
	copy(c.Head.Journal[:], plain[56:72])
	c.Head.KernelVersion = 1
	c.Head.Revision = binary.BigEndian.Uint64(plain[72:80])
	copy(c.Previous[:], plain[80:96])
	copy(c.PreviousHash[:], plain[96:128])
	copy(c.BatchHash[:], plain[128:160])
	c.Head.LastID = binary.BigEndian.Uint64(plain[160:168])
	copy(c.Head.Call[:], plain[168:184])
	c.Head.ControlOne = hex.EncodeToString(plain[184:216])
	c.Head.ControlTwo = hex.EncodeToString(plain[216:248])
	if c.ID == uuid.Nil || c.Head.Call == uuid.Nil || c.Head.Revision > kernelMaxBatches || c.Head.LastID > kernelMaxBatches*4095 || c.BatchHash != sha256.Sum256(batch) {
		return fail()
	}
	if data[6] == 0 {
		if n != 0 || c.Head.Revision != 0 || c.Head.LastID != 0 || c.Previous != uuid.Nil || c.PreviousHash != [32]byte{} {
			return fail()
		}
	} else {
		if n == 0 || c.Head.Revision == 0 || c.Head.LastID == 0 || c.Previous == uuid.Nil || c.Previous == c.ID || c.PreviousHash == [32]byte{} {
			return fail()
		}
		c.Head.Tip, c.Head.TipHash = c.ID, hex.EncodeToString(c.BatchHash[:])
	}
	return c, batch, nil
}

func (k *containerKernel) allocated() (int64, error) {
	unit, err := k.dir.AllocationUnit()
	if err != nil {
		return 0, err
	}
	if unit != 4096 {
		return 0, errors.New("kernel requires reviewed 4096-byte allocation unit")
	}
	var size int64
	count := 0
	err = k.dir.WalkEntries(func(name string) error {
		count++
		if count > kernelMaxBatches+16 {
			return errors.New("kernel inventory bound")
		}
		var n int64
		var err error
		if strings.HasPrefix(name, ".securestore-") || strings.HasPrefix(name, ".usage-") {
			n, err = k.dir.MetadataAllocatedSize(name)
		} else {
			n, err = k.dir.AllocatedSize(name)
		}
		if err != nil {
			return err
		}
		size += n
		if size > containerDiskBudget {
			return errors.New("kernel disk capacity")
		}
		return nil
	})
	// Four MiB independently covers bounded directory/metadata growth and
	// reconciliation work; all currently materialized child blocks counted above.
	return size + (4 << 20), err
}

func (k *containerKernel) commit(pdus [][]byte, callback func(securestore.Outcome, error)) (out securestore.Outcome, resultErr error) {
	out = securestore.NotCommitted
	defer func() {
		if resultErr != nil {
			resultErr = &securestore.CommitError{Outcome: out, Op: "kernel head container", Err: resultErr}
			k.fault = resultErr
		}
		for range pdus {
			callback(out, resultErr)
		}
	}()
	if k.fault != nil {
		return out, k.fault
	}
	if k.head.Revision >= 40 {
		return out, errors.New("kernel measurement transaction bound")
	}
	if len(pdus) == 0 || len(pdus) > 4095 {
		return out, errors.New("kernel input count bound")
	}
	inputBytes := 0
	for _, pdu := range pdus {
		if len(pdu) > kernelMaxPlain-inputBytes {
			return out, errors.New("kernel input byte bound")
		}
		inputBytes += len(pdu)
	}
	// Reserve the entire worst-case candidate before any new product encryption.
	const roundedContainer = 513 * 4096
	if k.retained > containerDiskBudget-roundedContainer {
		return out, errors.New("kernel pending container capacity")
	}
	old, err := k.dir.Read(".head", containerMaxBytes)
	if err != nil || sha256.Sum256(old) != k.selectedHash {
		return out, errors.New("kernel selected head changed before publication")
	}
	if _, _, err := k.decodeContainer(old); err != nil {
		return out, err
	}
	id, batch, err := k.encodeBatch(pdus)
	if err != nil {
		return out, err
	}
	head := k.head
	head.Revision++
	head.LastID += uint64(len(pdus))
	head.Tip, head.TipHash = id, kernelDigest(batch)
	candidate := kernelContainer{ID: id, Previous: k.selected.ID, PreviousHash: k.selectedHash, BatchHash: sha256.Sum256(batch), Head: head}
	data, err := k.encodeContainer(candidate, batch)
	if err != nil {
		return out, err
	}
	out, err = k.publish(containerStage(id), ".head", containerArchive(k.selected.ID), data)
	// Keep conservative allocation charged even after a publication fault.
	k.retained += roundedContainer
	if out == securestore.Committed {
		k.head = head
		k.selected = candidate
		k.selectedHash = sha256.Sum256(data)
	}
	if err == nil && out != securestore.Committed {
		err = errors.New("kernel container not definitely committed")
	}
	return out, err
}

func (k *containerKernel) validateControls() error {
	for destination, expected := range []string{k.head.ControlOne, k.head.ControlTwo} {
		data, err := k.dir.Read(fmt.Sprintf("control-%d", destination), 4096)
		if err != nil || kernelDigest(data) != expected {
			return errors.New("kernel control missing or corrupt")
		}
		plain, err := k.keys.Open(securestore.CallControl, k.controlBinding(destination), data, 1024)
		if err != nil || string(plain) != "kernel-only synthetic durable call-open dependency" {
			return errors.New("kernel control authentication failed")
		}
	}
	return nil
}

func (k *containerKernel) recoverContainers() error {
	archives := make(map[string]bool)
	stage := ""
	count := 0
	err := k.dir.WalkEntries(func(name string) error {
		count++
		if count > kernelMaxBatches+16 {
			return errors.New("kernel inventory bound")
		}
		switch {
		case name == ".head" || name == "control-0" || name == "control-1":
			return nil
		case strings.HasPrefix(name, "head-"):
			if _, ok := containerNameID(name, "head-", ".lhc"); !ok || len(archives) >= kernelMaxBatches {
				return errors.New("kernel archive name or count invalid")
			}
			archives[name] = false
			return nil
		case strings.HasPrefix(name, ".lch-stage-"):
			if _, ok := containerNameID(name, ".lch-stage-", ".tmp"); !ok || stage != "" {
				return &containerStageError{"invalid or multiple stages"}
			}
			stage = name
			return nil
		default:
			_, err := k.dir.MetadataAllocatedSize(name)
			return err
		}
	})
	if err != nil {
		return err
	}
	data, err := k.dir.Read(".head", containerMaxBytes)
	if err != nil {
		return err
	}
	current, batch, err := k.decodeContainer(data)
	if err != nil {
		return err
	}
	k.selected, k.selectedHash, k.head = current, sha256.Sum256(data), current.Head
	if err := k.validateControls(); err != nil {
		return err
	}
	stageKind := ""
	seen := make(map[uuid.UUID]bool)
	for {
		if seen[current.ID] {
			return errors.New("kernel repeated container UUID")
		}
		seen[current.ID] = true
		if current.Head.Call != k.head.Call || current.Head.Journal != k.head.Journal || current.Head.ControlOne != k.head.ControlOne || current.Head.ControlTwo != k.head.ControlTwo {
			return errors.New("kernel container identity changed")
		}
		if current.Head.Revision == 0 {
			break
		}
		prevBatch, prevDigest, prevLast, err := k.readBatch(current.ID, current.Head.Revision, current.Head.LastID, batch)
		if err != nil {
			return err
		}
		name := containerArchive(current.Previous)
		if _, exists := archives[name]; exists {
			if archives[name] {
				return errors.New("kernel archive repeated")
			}
			archives[name] = true
			data, err = k.dir.Read(name, containerMaxBytes)
		} else if current.ID == k.selected.ID && stage == containerStage(current.ID) && stageKind == "" {
			data, err = k.dir.Read(stage, containerMaxBytes)
			stageKind = "displaced predecessor"
		} else {
			return errors.New("kernel selected predecessor missing")
		}
		if err != nil || sha256.Sum256(data) != current.PreviousHash {
			return errors.New("kernel selected predecessor missing or corrupt")
		}
		previous, previousBatch, err := k.decodeContainer(data)
		if err != nil {
			return err
		}
		if previous.ID != current.Previous || previous.Head.Revision+1 != current.Head.Revision || previous.Head.LastID != prevLast || previous.Head.Tip != prevBatch || previous.Head.TipHash != prevDigest {
			return errors.New("kernel predecessor continuity invalid")
		}
		current, batch = previous, previousBatch
	}
	for _, used := range archives {
		if !used {
			return errors.New("kernel unreferenced archive")
		}
	}
	if stage != "" {
		if stageKind == "" {
			data, err := k.dir.Read(stage, containerMaxBytes)
			if err != nil {
				return &containerStageError{"unclassified stage"}
			}
			candidate, batch, err := k.decodeContainer(data)
			id, _ := containerNameID(stage, ".lch-stage-", ".tmp")
			if err != nil || candidate.ID != id || candidate.Previous != k.selected.ID || candidate.PreviousHash != k.selectedHash || candidate.Head.Revision != k.head.Revision+1 {
				return &containerStageError{"unclassified stage"}
			}
			prev, digest, last, err := k.readBatch(candidate.ID, candidate.Head.Revision, candidate.Head.LastID, batch)
			if err != nil || prev != k.head.Tip || digest != k.head.TipHash || last != k.head.LastID || candidate.Head.Call != k.head.Call || candidate.Head.ControlOne != k.head.ControlOne || candidate.Head.ControlTwo != k.head.ControlTwo {
				return &containerStageError{"unclassified stage"}
			}
			stageKind = "unpublished candidate"
		}
		return &containerStageError{stageKind}
	}
	return nil
}
