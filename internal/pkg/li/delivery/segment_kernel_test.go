//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const (
	segmentSize         = securestore.FixedSegmentBytes
	segmentBlock        = securestore.FixedSegmentBlock
	segmentDataStart    = securestore.FixedSegmentDataStart
	segmentHeadPayload  = 288
	segmentDiskBudget   = 96 << 20
	segmentScratchBytes = 16 << 20
	segmentMaxPDUHeader = 4096
)

var errSegmentPDU = errors.New("kernel segment PDU framing or header bound")

// Bound object allocation before the general PDU decoder creates TLV slices.
// This experimental 4 KiB header limit is not a production compatibility claim.
func segmentPDUPreflight(data []byte) error {
	if len(data) < x2x3.HeaderMinSize || len(data) > kernelMaxPlain {
		return errSegmentPDU
	}
	header := uint64(binary.BigEndian.Uint32(data[4:8]))
	payload := uint64(binary.BigEndian.Uint32(data[8:12]))
	if header < x2x3.HeaderMinSize || header > segmentMaxPDUHeader || header+payload != uint64(len(data)) {
		return errSegmentPDU
	}
	for offset := uint64(x2x3.HeaderMinSize); offset < header; {
		if header-offset < 4 {
			return errSegmentPDU
		}
		n := uint64(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if n > header-offset-4 {
			return errSegmentPDU
		}
		offset += 4 + n
	}
	return nil
}

type segmentHead struct {
	Generation               uint64
	Previous                 [32]byte
	Cursor, LastOffset       uint64
	LastLength, Transactions uint32
	Tip                      uuid.UUID
	Digest                   [32]byte
	LastID                   uint64
	Call                     uuid.UUID
	Controls                 [2][32]byte
}
type segmentKernel struct {
	*batchKernel
	mu        sync.Mutex
	file      *securestore.FixedSegment
	header    [segmentBlock]byte
	segmentID uuid.UUID
	slots     [2][]byte
	heads     [2]segmentHead
	active    uint8
	publish   func([]byte, []byte) (securestore.Outcome, error)
}
type segmentTailError struct{}

func (*segmentTailError) Error() string {
	return "kernel bounded unselected segment tail requires offline reconciliation"
}
func (k *segmentKernel) close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	var err error
	if k.file != nil {
		err = k.file.Close()
	}
	return errors.Join(err, k.batchKernel.close())
}

func segmentHeader(id uuid.UUID) [segmentBlock]byte {
	var data [segmentBlock]byte
	copy(data[:], "LSG1")
	data[4], data[5] = 1, 2
	copy(data[8:24], id[:])
	binary.BigEndian.PutUint64(data[24:32], segmentSize)
	for i, n := range []uint32{4096, 8192, 4096, 12288, kernelMaxFile, 4096, 4096, 0} {
		binary.BigEndian.PutUint32(data[32+i*4:36+i*4], n)
	}
	return data
}
func (k *segmentKernel) validateHeader(data []byte) error {
	if len(data) != segmentBlock {
		return errors.New("kernel segment header size")
	}
	var id uuid.UUID
	copy(id[:], data[8:24])
	expected := segmentHeader(id)
	if id == uuid.Nil || !bytes.Equal(data, expected[:]) {
		return errors.New("kernel segment header invalid")
	}
	k.segmentID = id
	copy(k.header[:], data)
	return nil
}
func (k *segmentKernel) encodeSlot(h segmentHead) ([]byte, error) {
	data := make([]byte, segmentBlock)
	copy(data, "LSH1")
	data[4] = 1
	data[5] = byte(h.Generation % 2)
	binary.BigEndian.PutUint32(data[8:12], uint32(367+len(kernelKeyID)))
	plain := make([]byte, segmentHeadPayload)
	copy(plain, "LSP1")
	binary.BigEndian.PutUint16(plain[4:6], 1)
	if h.Transactions != 0 {
		plain[6] = 1
	}
	copy(plain[8:24], data[:16])
	store := k.usage.StoreID()
	copy(plain[24:40], store[:])
	copy(plain[40:56], k.segmentID[:])
	headerDigest := sha256.Sum256(k.header[:])
	copy(plain[56:88], headerDigest[:])
	binary.BigEndian.PutUint64(plain[88:96], h.Generation)
	copy(plain[96:128], h.Previous[:])
	binary.BigEndian.PutUint64(plain[128:136], h.Cursor)
	binary.BigEndian.PutUint64(plain[136:144], h.LastOffset)
	binary.BigEndian.PutUint32(plain[144:148], h.LastLength)
	binary.BigEndian.PutUint32(plain[148:152], h.Transactions)
	copy(plain[152:168], h.Tip[:])
	copy(plain[168:200], h.Digest[:])
	binary.BigEndian.PutUint64(plain[200:208], h.LastID)
	copy(plain[208:224], h.Call[:])
	copy(plain[224:256], h.Controls[0][:])
	copy(plain[256:288], h.Controls[1][:])
	sealed, err := k.writer.Seal(securestore.JournalState, k.binding("journal-state"), plain)
	if err != nil {
		return nil, err
	}
	if len(sealed) != 367+len(kernelKeyID) {
		return nil, errors.New("kernel segment head length")
	}
	copy(data[16:], sealed)
	return data, nil
}
func (k *segmentKernel) decodeSlot(data []byte, slot uint8) (segmentHead, error) {
	fail := func() (segmentHead, error) {
		return segmentHead{}, errors.New("kernel authenticated segment head invalid")
	}
	if len(data) != segmentBlock || slot > 1 || string(data[:4]) != "LSH1" || data[4] != 1 || data[5] != slot || data[6] != 0 || data[7] != 0 || !bytes.Equal(data[12:16], make([]byte, 4)) {
		return fail()
	}
	n := binary.BigEndian.Uint32(data[8:12])
	if n < 368 || n > 431 || !bytes.Equal(data[16+n:], make([]byte, segmentBlock-16-int(n))) {
		return fail()
	}
	sealed := data[16 : 16+n]
	if int(n) != 367+int(binary.BigEndian.Uint16(sealed[8:10])) {
		return fail()
	}
	p, err := k.keys.Open(securestore.JournalState, k.binding("journal-state"), sealed, segmentHeadPayload)
	store := k.usage.StoreID()
	digest := sha256.Sum256(k.header[:])
	if err != nil || len(p) != segmentHeadPayload || string(p[:4]) != "LSP1" || binary.BigEndian.Uint16(p[4:6]) != 1 || p[6] > 1 || p[7] != 0 || !bytes.Equal(p[8:24], data[:16]) || !bytes.Equal(p[24:40], store[:]) || !bytes.Equal(p[40:56], k.segmentID[:]) || !bytes.Equal(p[56:88], digest[:]) {
		return fail()
	}
	var h segmentHead
	h.Generation = binary.BigEndian.Uint64(p[88:96])
	copy(h.Previous[:], p[96:128])
	h.Cursor = binary.BigEndian.Uint64(p[128:136])
	h.LastOffset = binary.BigEndian.Uint64(p[136:144])
	h.LastLength = binary.BigEndian.Uint32(p[144:148])
	h.Transactions = binary.BigEndian.Uint32(p[148:152])
	copy(h.Tip[:], p[152:168])
	copy(h.Digest[:], p[168:200])
	h.LastID = binary.BigEndian.Uint64(p[200:208])
	copy(h.Call[:], p[208:224])
	copy(h.Controls[0][:], p[224:256])
	copy(h.Controls[1][:], p[256:288])
	if h.Generation > kernelMaxBatches+1 || h.Generation%2 != uint64(slot) || h.Call == uuid.Nil || h.Cursor < segmentDataStart || h.Cursor > segmentSize || h.Cursor%segmentBlock != 0 || h.LastID > kernelMaxBatches*4095 {
		return fail()
	}
	if p[6] == 0 {
		if h.Generation > 1 || h.Transactions != 0 || h.Cursor != segmentDataStart || h.LastOffset != 0 || h.LastLength != 0 || h.Tip != uuid.Nil || h.Digest != [32]byte{} || h.LastID != 0 {
			return fail()
		}
		if h.Generation == 0 && h.Previous != [32]byte{} || h.Generation == 1 && h.Previous == [32]byte{} {
			return fail()
		}
	} else {
		if h.Transactions == 0 || h.Transactions > kernelMaxBatches || h.Generation != uint64(h.Transactions)+1 || h.Previous == [32]byte{} || h.Tip == uuid.Nil || h.Digest == [32]byte{} || h.LastID == 0 || h.LastLength < kernelPrefixBytes || h.LastLength > kernelMaxFile || h.LastOffset < segmentDataStart || h.LastOffset > segmentSize || h.LastOffset%segmentBlock != 0 {
			return fail()
		}
		span := (uint64(h.LastLength) + segmentBlock - 1) / segmentBlock * segmentBlock
		if h.LastOffset > h.Cursor || span > segmentSize-h.LastOffset || h.Cursor-h.LastOffset != span {
			return fail()
		}
	}
	return h, nil
}
func (k *segmentKernel) decodePair(raw [2][]byte) ([2]segmentHead, uint8, error) {
	var heads [2]segmentHead
	for i := range heads {
		h, err := k.decodeSlot(raw[i], uint8(i))
		if err != nil {
			return heads, 0, err
		}
		heads[i] = h
	}
	high := uint8(0)
	if heads[1].Generation > heads[0].Generation {
		high = 1
	}
	hi, lo := heads[high], heads[high^1]
	if hi.Generation != lo.Generation+1 || hi.Previous != sha256.Sum256(raw[high^1]) || hi.Call != lo.Call || hi.Controls != lo.Controls || hi.Cursor < lo.Cursor || hi.LastID < lo.LastID {
		return heads, high, errors.New("kernel segment head pair disagrees")
	}
	if hi.Generation == 1 {
		if lo.Generation != 0 || hi.Transactions != 0 || lo.Transactions != 0 {
			return heads, high, errors.New("kernel invalid bootstrap pair")
		}
	} else if hi.Transactions != lo.Transactions+1 || hi.Cursor <= lo.Cursor || hi.LastOffset != lo.Cursor || hi.LastID <= lo.LastID {
		return heads, high, errors.New("kernel segment transition invalid")
	}
	return heads, high, nil
}
func (k *segmentKernel) setLogical(h segmentHead) {
	k.head = kernelHead{KernelVersion: 1, Journal: uuid.UUID(k.usage.StoreID()), Revision: uint64(h.Transactions), LastID: h.LastID, Call: h.Call, ControlOne: hex.EncodeToString(h.Controls[0][:]), ControlTwo: hex.EncodeToString(h.Controls[1][:])}
	if h.Transactions > 0 {
		k.head.Tip = h.Tip
		k.head.TipHash = hex.EncodeToString(h.Digest[:])
	}
}
func openSegmentKernel(dir, keyFile string, initialize bool) (_ *segmentKernel, resultErr error) {
	k := &segmentKernel{batchKernel: &batchKernel{preflightPDU: segmentPDUPreflight}}
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
		if err := k.dir.WalkEntries(func(string) error { return errors.New("kernel segment initialization requires empty directory") }); err != nil {
			return nil, err
		}
	}
	k.lock, err = k.dir.Lock("segment.lsg")
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
			return nil, errors.Join(err, errors.New("kernel segment usage initialization failed"))
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
	if initialize {
		k.segmentID, err = uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		k.header = segmentHeader(k.segmentID)
		k.head.Call, err = uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		root := segmentHead{Cursor: segmentDataStart, Call: k.head.Call}
		for destination := range calibrationDIDs {
			data, err := k.writer.SealControl(securestore.CallControl, k.controlBinding(destination), []byte("kernel-only synthetic durable call-open dependency"))
			if err != nil {
				return nil, err
			}
			out, err := k.dir.Create(fmt.Sprintf("control-%d", destination), data)
			if err != nil || out != securestore.Committed {
				return nil, errors.Join(err, errors.New("kernel segment control initialization failed"))
			}
			root.Controls[destination] = sha256.Sum256(data)
		}
		k.slots[0], err = k.encodeSlot(root)
		if err != nil {
			return nil, err
		}
		root.Generation = 1
		root.Previous = sha256.Sum256(k.slots[0])
		k.slots[1], err = k.encodeSlot(root)
		if err != nil {
			return nil, err
		}
		bootstrap := make([]byte, segmentDataStart)
		copy(bootstrap, k.header[:])
		copy(bootstrap[segmentBlock:], k.slots[0])
		copy(bootstrap[2*segmentBlock:], k.slots[1])
		stage := ".lsg-init-" + hex.EncodeToString(k.segmentID[:]) + ".tmp"
		out, err := k.dir.InitializeFixedSegment(stage, "segment.lsg", bootstrap)
		if err != nil || out != securestore.Committed {
			return nil, errors.Join(err, errors.New("kernel segment bootstrap publication failed"))
		}
	}
	k.file, err = k.dir.OpenFixedSegment("segment.lsg")
	if err != nil {
		return nil, err
	}
	k.publish = k.file.Commit
	if err := k.recoverSegment(); err != nil {
		return nil, err
	}
	if err := k.file.Activate(int64(k.heads[k.active].Cursor), k.active); err != nil {
		return nil, err
	}
	return k, nil
}
func (k *segmentKernel) readAuthority() ([2][]byte, [2]segmentHead, uint8, error) {
	rawHeader := make([]byte, segmentBlock)
	var raw [2][]byte
	if err := k.file.ReadAt(rawHeader, 0); err != nil {
		return raw, [2]segmentHead{}, 0, err
	}
	if err := k.validateHeader(rawHeader); err != nil {
		return raw, [2]segmentHead{}, 0, err
	}
	for i := range raw {
		raw[i] = make([]byte, segmentBlock)
		if err := k.file.ReadAt(raw[i], int64(i+1)*segmentBlock); err != nil {
			return raw, [2]segmentHead{}, 0, err
		}
	}
	heads, active, err := k.decodePair(raw)
	return raw, heads, active, err
}
func segmentMatches(h segmentHead, cursor, offset uint64, length uint32, id uuid.UUID, digest [32]byte, last uint64) bool {
	return h.Cursor == cursor && h.LastOffset == offset && h.LastLength == length && h.Tip == id && h.Digest == digest && h.LastID == last
}
func (k *segmentKernel) recoverSegment() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	count := 0
	charged := int64(4 << 20)
	if err := k.dir.WalkEntries(func(name string) error {
		count++
		if count > 12 {
			return errors.New("kernel segment inventory bound")
		}
		var n int64
		var err error
		switch name {
		case "segment.lsg", "control-0", "control-1":
			n, err = k.dir.AllocatedSize(name)
		default:
			n, err = k.dir.MetadataAllocatedSize(name)
		}
		if err != nil {
			return err
		}
		charged += n
		if charged > segmentDiskBudget {
			return errors.New("kernel segment disk budget")
		}
		return nil
	}); err != nil {
		return err
	}
	raw, heads, active, err := k.readAuthority()
	if err != nil {
		return err
	}
	high, low := heads[active], heads[active^1]
	k.setLogical(high)
	for i, expected := range high.Controls {
		data, err := k.dir.Read(fmt.Sprintf("control-%d", i), 4096)
		if err != nil || sha256.Sum256(data) != expected {
			return errors.New("kernel segment control missing or corrupt")
		}
		plain, err := k.keys.Open(securestore.CallControl, k.controlBinding(i), data, 1024)
		if err != nil || string(plain) != "kernel-only synthetic durable call-open dependency" {
			return errors.New("kernel segment control authentication failed")
		}
	}
	cursor := uint64(segmentDataStart)
	var last, offset uint64
	var length uint32
	var tip uuid.UUID
	var digest [32]byte
	seen := make(map[uuid.UUID]bool)
	for transaction := uint32(1); transaction <= high.Transactions; transaction++ {
		if cursor > high.Cursor || high.Cursor-cursor < kernelPrefixBytes {
			return errors.New("kernel selected segment frame missing")
		}
		prefix := make([]byte, kernelPrefixBytes)
		if err := k.file.ReadAt(prefix, int64(cursor)); err != nil {
			return err
		}
		n := binary.BigEndian.Uint64(prefix[32:40])
		frames := binary.BigEndian.Uint32(prefix[24:28])
		if n < kernelPrefixBytes || n > kernelMaxFile || frames < 2 || frames > 4096 {
			return errors.New("kernel segment frame bounds")
		}
		span := (n + segmentBlock - 1) / segmentBlock * segmentBlock
		if span > high.Cursor-cursor {
			return errors.New("kernel selected segment span truncated")
		}
		data := make([]byte, int(span))
		if err := k.file.ReadAt(data, int64(cursor)); err != nil {
			return err
		}
		if !bytes.Equal(data[n:], make([]byte, span-n)) {
			return errors.New("kernel committed segment padding corrupt")
		}
		var id uuid.UUID
		copy(id[:], prefix[8:24])
		if seen[id] {
			return errors.New("kernel repeated segment batch UUID")
		}
		seen[id] = true
		next := last + uint64(frames-1)
		previous, hash, priorLast, err := k.readBatch(id, uint64(transaction), next, data[:n])
		if err != nil {
			return err
		}
		expectedHash := ""
		if transaction > 1 {
			expectedHash = hex.EncodeToString(digest[:])
		}
		if previous != tip || hash != expectedHash || priorLast != last {
			return errors.New("kernel segment batch chain invalid")
		}
		offset, length, tip, digest, last = cursor, uint32(n), id, sha256.Sum256(data[:n]), next
		cursor += span
		if transaction == low.Transactions && !segmentMatches(low, cursor, offset, length, tip, digest, last) {
			return errors.New("kernel lower head selected boundary mismatch")
		}
	}
	if !segmentMatches(high, cursor, offset, length, tip, digest, last) {
		return errors.New("kernel higher head selected boundary mismatch")
	}
	buffer := make([]byte, 64<<10)
	dirty := false
	allowed := min(uint64(kernelMaxFile), uint64(segmentSize)-high.Cursor)
	for offset := high.Cursor; offset < segmentSize; {
		n := min(uint64(len(buffer)), uint64(segmentSize)-offset)
		if err := k.file.ReadAt(buffer[:n], int64(offset)); err != nil {
			return err
		}
		for i, b := range buffer[:n] {
			if b != 0 {
				if offset+uint64(i)-high.Cursor >= allowed {
					return errors.New("kernel segment nonzero tail exceeds one attempt")
				}
				dirty = true
			}
		}
		offset += n
	}
	if dirty {
		return &segmentTailError{}
	}
	k.slots, k.heads, k.active = raw, heads, active
	return nil
}
func (k *segmentKernel) commit(pdus [][]byte, callback func(securestore.Outcome, error)) (out securestore.Outcome, resultErr error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out = securestore.NotCommitted
	defer func() {
		if resultErr != nil {
			resultErr = &securestore.CommitError{Outcome: out, Op: "kernel segment commit", Err: resultErr}
			k.fault = resultErr
		}
		for range pdus {
			callback(out, resultErr)
		}
	}()
	if k.fault != nil {
		return out, k.fault
	}
	current := k.heads[k.active]
	if current.Transactions >= 40 || len(pdus) == 0 || len(pdus) > 4095 || current.Cursor > segmentSize-kernelMaxFile {
		return out, errors.New("kernel segment admission bound")
	}
	total := 0
	for _, pdu := range pdus {
		if len(pdu) > kernelMaxPlain-total {
			return out, errors.New("kernel segment input byte bound")
		}
		total += len(pdu)
	}
	oldHeader := k.header
	raw, heads, active, err := k.readAuthority()
	if err != nil {
		return out, err
	}
	if oldHeader != k.header || active != k.active || heads != k.heads || !bytes.Equal(raw[0], k.slots[0]) || !bytes.Equal(raw[1], k.slots[1]) {
		return out, errors.New("kernel segment authority changed before publication")
	}
	id, batch, err := k.encodeBatch(pdus)
	if err != nil {
		return out, err
	}
	span := (len(batch) + segmentBlock - 1) / segmentBlock * segmentBlock
	padded := make([]byte, span)
	copy(padded, batch)
	next := current
	next.Generation++
	next.Transactions++
	next.Previous = sha256.Sum256(k.slots[k.active])
	next.LastOffset = current.Cursor
	next.LastLength = uint32(len(batch))
	next.Cursor += uint64(span)
	next.Tip = id
	next.Digest = sha256.Sum256(batch)
	next.LastID += uint64(len(pdus))
	slot, err := k.encodeSlot(next)
	if err != nil {
		return out, err
	}
	out, err = k.publish(padded, slot)
	if out == securestore.Committed {
		k.active ^= 1
		k.slots[k.active] = slot
		k.heads[k.active] = next
		k.setLogical(next)
	}
	if err == nil && out != securestore.Committed {
		err = errors.New("kernel segment not definitely committed")
	}
	return out, err
}
