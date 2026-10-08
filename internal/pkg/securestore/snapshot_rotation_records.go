package securestore

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"unicode/utf8"
)

// These codecs describe offline snapshot rotation only. They neither acquire
// ownership nor authorize initialization, publication, or cleanup. The caller
// must authenticate the selected protocol state under retained ownership first.
const (
	snapshotRotationRequestMax     = 4096
	snapshotRotationRecordMax      = 16 << 10
	snapshotRotationBootstrapBytes = 88
)

var errSnapshotRotationRecord = errors.New("securestore: invalid snapshot rotation record")

type snapshotRotationRequest struct {
	Purpose                                   Purpose
	InPlace                                   bool
	Store                                     [16]byte
	Parent, Source                            FileIdentity
	SourcePath, DestinationPath               [32]byte
	SourceCiphertext, Payload                 [32]byte
	SourceRing                                [32]byte
	PredecessorBootstrap, PredecessorProgress [32]byte
	SourceEnvelopeBytes, PayloadBytes         uint64
	Object, SourceName, DestinationName       string
	SourceKeyID, NewKeyID                     string
}

func (r snapshotRotationRequest) valid() bool {
	if (r.Purpose != FilterSnapshot && r.Purpose != AdministrativeState && r.Purpose != CallCorrelationState) ||
		r.Store == [16]byte{} || r.Parent.Inode == 0 || r.Source.Inode == 0 ||
		r.SourcePath == [32]byte{} || r.DestinationPath == [32]byte{} ||
		r.SourceCiphertext == [32]byte{} || r.Payload == [32]byte{} || r.SourceRing == [32]byte{} ||
		(r.PredecessorBootstrap == [32]byte{}) != (r.PredecessorProgress == [32]byte{}) ||
		!validKeyID(r.SourceKeyID) || !validKeyID(r.NewKeyID) || r.SourceKeyID == r.NewKeyID ||
		!(Binding{Store: r.Store, Object: r.Object}).valid() ||
		checkName(r.SourceName) != nil || checkName(r.DestinationName) != nil ||
		!utf8.ValidString(r.SourceName) || !utf8.ValidString(r.DestinationName) ||
		r.InPlace != (r.SourceName == r.DestinationName) ||
		r.SourceEnvelopeBytes < fixedHeaderBytes+1+nonceBytes+tagBytes+bindingFixedBytes+1 ||
		r.SourceEnvelopeBytes > MaxEnvelopeBytes ||
		r.PayloadBytes > uint64(MaxPlaintextBytes-bindingFixedBytes-len(r.Object)) {
		return false
	}
	return true
}

func appendRotationString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func (r snapshotRotationRequest) marshal() ([]byte, error) {
	if !r.valid() {
		return nil, errSnapshotRotationRecord
	}
	b := make([]byte, 0, snapshotRotationRequestMax)
	b = append(b, 'L', 'R', 'Q', '1', 1, 0)
	if r.InPlace {
		b[5] = 1
	}
	b = binary.BigEndian.AppendUint16(b, uint16(r.Purpose))
	b = append(b, r.Store[:]...)
	for _, n := range []uint64{r.Parent.Device, r.Parent.Inode, r.Source.Device, r.Source.Inode, r.SourceEnvelopeBytes, r.PayloadBytes} {
		b = binary.BigEndian.AppendUint64(b, n)
	}
	for _, digest := range [][32]byte{r.SourcePath, r.DestinationPath, r.SourceCiphertext, r.Payload, r.SourceRing, r.PredecessorBootstrap, r.PredecessorProgress} {
		b = append(b, digest[:]...)
	}
	for _, s := range []string{r.Object, r.SourceName, r.DestinationName, r.SourceKeyID, r.NewKeyID} {
		b = appendRotationString(b, s)
	}
	if len(b) > snapshotRotationRequestMax {
		return nil, errSnapshotRotationRecord
	}
	return b, nil
}

type snapshotRotationReader struct {
	b   []byte
	bad bool
}

func (r *snapshotRotationReader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}

func (r *snapshotRotationReader) number() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (r *snapshotRotationReader) text(limit int) string {
	b := r.take(2)
	if len(b) != 2 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(b))
	if n > limit {
		r.bad = true
		return ""
	}
	return string(r.take(n))
}

func parseSnapshotRotationRequest(b []byte) (snapshotRotationRequest, error) {
	var out snapshotRotationRequest
	if len(b) < 8 || len(b) > snapshotRotationRequestMax || string(b[:4]) != "LRQ1" || b[4] != 1 || b[5] > 1 {
		return out, errSnapshotRotationRecord
	}
	out.InPlace, out.Purpose = b[5] == 1, Purpose(binary.BigEndian.Uint16(b[6:8]))
	r := snapshotRotationReader{b: b[8:]}
	copy(out.Store[:], r.take(16))
	out.Parent = FileIdentity{r.number(), r.number()}
	out.Source = FileIdentity{r.number(), r.number()}
	out.SourceEnvelopeBytes, out.PayloadBytes = r.number(), r.number()
	for _, digest := range []*[32]byte{&out.SourcePath, &out.DestinationPath, &out.SourceCiphertext, &out.Payload, &out.SourceRing, &out.PredecessorBootstrap, &out.PredecessorProgress} {
		copy(digest[:], r.take(32))
	}
	out.Object = r.text(MaxObjectIDBytes)
	out.SourceName, out.DestinationName = r.text(255), r.text(255)
	out.SourceKeyID, out.NewKeyID = r.text(MaxKeyIDBytes), r.text(MaxKeyIDBytes)
	if r.bad || len(r.b) != 0 || !out.valid() {
		return snapshotRotationRequest{}, errSnapshotRotationRecord
	}
	return out, nil
}

// Commitment includes raw source material under the NEW key's separate HMAC
// domain. It is opaque outside encrypted progress; never print it as a key label.
// Key paths and inode replacement do not change immutable loaded key material.
func snapshotRotationRingCommitment(source, target *Keyring) ([32]byte, error) {
	var out [32]byte
	if source == nil || source.active == nil || len(source.keys) == 0 || len(source.keys) > 1+MaxPriorKeys || target == nil || target.active == nil || len(target.keys) != 1 || source.legacy != nil || target.legacy != nil {
		return out, errSnapshotRotationRecord
	}
	if err := CheckIndependent(source, target); err != nil {
		return out, err
	}
	if _, exists := source.keys[target.active.id]; exists {
		return out, errSnapshotRotationRecord
	}
	ids := make([]string, 0, len(source.keys))
	for id := range source.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// Allocate once so appending material cannot leave an uncleared previous
	// backing array behind during growth.
	b := make([]byte, 0, 2+MaxKeyIDBytes+len(ids)*(2+MaxKeyIDBytes+KeyBytes))
	b = appendRotationString(b, source.active.id)
	for _, id := range ids {
		b = appendRotationString(b, id)
		b = append(b, source.keys[id].raw[:]...)
	}
	defer clear(b)
	copy(out[:], target.active.mac("lippycat/securestore/rotation/source-ring/v1\x00", b))
	return out, nil
}

func snapshotRotationToken(r snapshotRotationRequest, target *Keyring) ([32]byte, error) {
	var out [32]byte
	if target == nil || target.active == nil || target.active.id != r.NewKeyID {
		return out, errSnapshotRotationRecord
	}
	b, err := r.marshal()
	if err != nil {
		return out, err
	}
	defer clear(b)
	copy(out[:], target.active.mac("lippycat/securestore/rotation/request/v1\x00", b))
	return out, nil
}

type snapshotRotationBootstrapStage byte

const (
	snapshotRotationUninitialized snapshotRotationBootstrapStage = 1
	snapshotRotationRequired      snapshotRotationBootstrapStage = 2
)

type snapshotRotationBootstrap struct {
	Stage   snapshotRotationBootstrapStage
	Purpose Purpose
	Store   [16]byte
	Token   [32]byte
}

func (r snapshotRotationBootstrap) valid() bool {
	return (r.Stage == snapshotRotationUninitialized || r.Stage == snapshotRotationRequired) &&
		(r.Purpose == FilterSnapshot || r.Purpose == AdministrativeState || r.Purpose == CallCorrelationState) && r.Store != [16]byte{} && r.Token != [32]byte{}
}

func (r snapshotRotationBootstrap) marshal(target *Keyring) ([]byte, error) {
	if !r.valid() || target == nil || target.active == nil {
		return nil, errSnapshotRotationRecord
	}
	b := make([]byte, snapshotRotationBootstrapBytes)
	copy(b, "LRU1")
	b[4], b[5] = 1, byte(r.Stage)
	binary.BigEndian.PutUint16(b[6:8], uint16(r.Purpose))
	copy(b[8:24], r.Store[:])
	copy(b[24:56], r.Token[:])
	copy(b[56:], target.active.mac("lippycat/securestore/rotation/bootstrap/v1\x00", b[:56]))
	return b, nil
}

func parseSnapshotRotationBootstrap(b []byte, target *Keyring) (snapshotRotationBootstrap, error) {
	var out snapshotRotationBootstrap
	if len(b) != snapshotRotationBootstrapBytes || string(b[:4]) != "LRU1" || b[4] != 1 || target == nil || target.active == nil {
		return out, errSnapshotRotationRecord
	}
	if !hmac.Equal(b[56:], target.active.mac("lippycat/securestore/rotation/bootstrap/v1\x00", b[:56])) {
		return out, ErrAuthentication
	}
	out.Stage, out.Purpose = snapshotRotationBootstrapStage(b[5]), Purpose(binary.BigEndian.Uint16(b[6:8]))
	copy(out.Store[:], b[8:24])
	copy(out.Token[:], b[24:56])
	if !out.valid() {
		return snapshotRotationBootstrap{}, errSnapshotRotationRecord
	}
	return out, nil
}

type snapshotRotationProgressStage byte

const (
	snapshotRotationPlanned  snapshotRotationProgressStage = 1
	snapshotRotationPrepared snapshotRotationProgressStage = 2
	snapshotRotationComplete snapshotRotationProgressStage = 3
)

type snapshotRotationProgress struct {
	Stage          snapshotRotationProgressStage
	Request        snapshotRotationRequest
	CandidateBytes uint64
	CandidateHash  [32]byte
}

func (r snapshotRotationProgress) valid() bool {
	if !r.Request.valid() {
		return false
	}
	if r.Stage == snapshotRotationPlanned {
		return r.CandidateBytes == 0 && r.CandidateHash == [32]byte{}
	}
	if r.Stage != snapshotRotationPrepared && r.Stage != snapshotRotationComplete {
		return false
	}
	// The exact final envelope length follows from the unchanged payload and
	// active key ID; candidate framing cannot silently change during resume.
	expected := uint64(fixedHeaderBytes+len(r.Request.NewKeyID)+nonceBytes+tagBytes+bindingFixedBytes+len(r.Request.Object)) + r.Request.PayloadBytes
	return r.CandidateHash != [32]byte{} && r.CandidateBytes == expected
}

func (r snapshotRotationProgress) marshal() ([]byte, error) {
	if !r.valid() {
		return nil, errSnapshotRotationRecord
	}
	request, err := r.Request.marshal()
	if err != nil {
		return nil, err
	}
	defer clear(request)
	b := make([]byte, 0, 52+len(request))
	b = append(b, 'L', 'R', 'P', '1', 1, byte(r.Stage), 0, 0)
	b = binary.BigEndian.AppendUint32(b, uint32(len(request)))
	b = binary.BigEndian.AppendUint64(b, r.CandidateBytes)
	b = append(b, r.CandidateHash[:]...)
	return append(b, request...), nil
}

func parseSnapshotRotationProgress(b []byte) (snapshotRotationProgress, error) {
	var out snapshotRotationProgress
	if len(b) < 52 || len(b) > 52+snapshotRotationRequestMax || string(b[:4]) != "LRP1" || b[4] != 1 || b[6] != 0 || b[7] != 0 || uint64(binary.BigEndian.Uint32(b[8:12])) != uint64(len(b)-52) {
		return out, errSnapshotRotationRecord
	}
	request, err := parseSnapshotRotationRequest(b[52:])
	if err != nil {
		return out, err
	}
	out.Stage, out.Request = snapshotRotationProgressStage(b[5]), request
	out.CandidateBytes = binary.BigEndian.Uint64(b[12:20])
	copy(out.CandidateHash[:], b[20:52])
	if !out.valid() {
		return snapshotRotationProgress{}, errSnapshotRotationRecord
	}
	return out, nil
}

func snapshotRotationProgressBinding(store [16]byte, destination, token [32]byte) Binding {
	return Binding{Store: store, Object: "snapshot-rotation/" + hex.EncodeToString(destination[:]) + "/" + hex.EncodeToString(token[:])}
}

func sealSnapshotRotationProgress(r snapshotRotationProgress, target *Keyring, writer *Writer) ([]byte, error) {
	if writer == nil || writer.usage == nil || target == nil || target.active == nil || writer.usage.key != target.active || writer.usage.StoreID() != r.Request.Store {
		return nil, errSnapshotRotationRecord
	}
	token, err := snapshotRotationToken(r.Request, target)
	if err != nil {
		return nil, err
	}
	b, err := r.marshal()
	if err != nil {
		return nil, err
	}
	defer clear(b)
	// All progress, including completion, uses ordinary capacity. Offline key
	// rotation must never borrow the control reserve from either key.
	return writer.Seal(r.Request.Purpose, snapshotRotationProgressBinding(r.Request.Store, r.Request.DestinationPath, token), b)
}

func openSnapshotRotationProgress(b []byte, target *Keyring, bootstrap snapshotRotationBootstrap, destination [32]byte) (snapshotRotationProgress, error) {
	var out snapshotRotationProgress
	if !bootstrap.valid() || bootstrap.Stage != snapshotRotationRequired || destination == [32]byte{} || target == nil || target.active == nil || len(b) > snapshotRotationRecordMax {
		return out, errSnapshotRotationRecord
	}
	plain, err := target.Open(bootstrap.Purpose, snapshotRotationProgressBinding(bootstrap.Store, destination, bootstrap.Token), b, 52+snapshotRotationRequestMax)
	if err != nil {
		return out, err
	}
	defer clear(plain)
	out, err = parseSnapshotRotationProgress(plain)
	if err != nil {
		return snapshotRotationProgress{}, err
	}
	token, err := snapshotRotationToken(out.Request, target)
	if err != nil || !hmac.Equal(token[:], bootstrap.Token[:]) || out.Request.Purpose != bootstrap.Purpose || out.Request.Store != bootstrap.Store || out.Request.DestinationPath != destination {
		return snapshotRotationProgress{}, ErrBinding
	}
	return out, nil
}
