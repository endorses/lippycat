//go:build linux

package securestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func (r *snapshotRotation) envelopeLimit() int64 {
	return r.owner.MaxPayloadBytes + MaxHeaderBytes + tagBytes + bindingFixedBytes + int64(len(r.owner.Object))
}
func (r *snapshotRotation) authenticate() error {
	for _, name := range []string{r.sourceName, r.destinationName, r.options.SourceKeys.UsageFileName(), r.options.NewKeys.UsageFileName(), r.names[RotationBootstrapUninitialized], r.names[RotationPlanned]} {
		if err := r.keyAliases(name); err != nil {
			return err
		}
	}
	exists, _, _, err := r.ledger(r.options.SourceKeys)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("securestore: required source usage ledger is missing")
	}
	r.newLedger, r.newSeals, r.newBlocks, err = r.ledger(r.options.NewKeys)
	if err != nil {
		return err
	}
	r.sourceCipher, err = r.dir.Read(r.sourceName, r.envelopeLimit())
	if err != nil {
		return err
	}
	r.sourceIdentity, err = r.dir.FileIdentity(r.sourceName)
	if err != nil {
		return err
	}
	r.bootstrapBytes, err = r.readOptional(r.names[RotationBootstrapUninitialized], snapshotRotationBootstrapBytes)
	if err != nil {
		return err
	}
	r.progressBytes, err = r.readOptional(r.names[RotationPlanned], snapshotRotationRecordMax)
	if err != nil {
		return err
	}
	if r.bootstrapBytes == nil && r.progressBytes != nil {
		return errors.New("securestore: rotation progress lacks bootstrap")
	}
	if r.bootstrapBytes != nil {
		current, openErr := parseSnapshotRotationBootstrap(r.bootstrapBytes, r.options.NewKeys)
		if openErr == nil {
			if !r.options.Resume {
				return errors.New("securestore: existing rotation requires explicit resume")
			}
			if current.Purpose != r.owner.Purpose || current.Store != r.store {
				return ErrBinding
			}
			r.bootstrap = current
			r.token = current.Token
			if current.Stage == snapshotRotationRequired && r.progressBytes != nil {
				p, err := openSnapshotRotationProgress(r.progressBytes, r.options.NewKeys, current, r.destinationPath)
				if err != nil {
					return err
				}
				r.progress = &p
				r.request = p.Request
			}
		} else {
			// A completed predecessor belongs to the destination's lineage. It cannot
			// stand in for a pending operation or an absent distinct destination.
			if !r.options.InPlace {
				return errors.New("securestore: destination has unrelated rotation metadata")
			}
			if _, err := r.completedReceipt(r.bootstrapBytes, r.progressBytes, r.options.SourceKeys, r.destinationPath, r.destinationName); err != nil {
				return err
			}
			r.predecessorBootstrap = append([]byte(nil), r.bootstrapBytes...)
			r.predecessorProgress = append([]byte(nil), r.progressBytes...)
			r.fresh = true
		}
	} else {
		r.fresh = true
	}
	if r.fresh && r.newLedger {
		return errors.New("securestore: fresh rotation key already has usage history")
	}
	if !r.fresh && r.bootstrap.Stage == snapshotRotationRequired && !r.newLedger {
		return errors.New("securestore: required new usage ledger is missing")
	}
	if !r.fresh && r.bootstrap.Stage == snapshotRotationUninitialized && r.newLedger && (r.newSeals != 0 || r.newBlocks != 0) {
		return errors.New("securestore: usage exists before ledger-required boundary")
	}
	if !r.fresh {
		r.names = rotationNames(r.owner.Purpose, r.destinationName, r.options.NewKeys.UsageFileName(), hex.EncodeToString(r.token[:]))
		if r.progress == nil {
			if err := r.loadPredecessors(); err != nil {
				return err
			}
		}
	}
	if r.progress != nil {
		if err := r.checkRequest(r.request); err != nil {
			return err
		}
	}
	// A distinct source's own receipt is historical lineage, never metadata for
	// this destination's transaction. A pending source rotation blocks this one.
	if !r.options.InPlace {
		if err := r.validateSourceLineage(); err != nil {
			return err
		}
	}
	complete := r.progress != nil && r.progress.Stage == snapshotRotationComplete
	prepared := r.progress != nil && r.progress.Stage >= snapshotRotationPrepared
	if r.options.InPlace && prepared {
		original := r.sourceIdentity == r.request.Source && sha256.Sum256(r.sourceCipher) == r.request.SourceCiphertext && uint64(len(r.sourceCipher)) == r.request.SourceEnvelopeBytes
		if !original || complete {
			if !complete && (sha256.Sum256(r.sourceCipher) != r.progress.CandidateHash || uint64(len(r.sourceCipher)) != r.progress.CandidateBytes) {
				return errors.New("securestore: pending destination changed")
			}
			r.payload, err = r.options.NewKeys.Open(r.owner.Purpose, Binding{Store: r.store, Object: r.owner.Object}, r.sourceCipher, int(r.owner.MaxPayloadBytes))
			if err != nil {
				return err
			}
			r.outputSelected = true
		}
	}
	if r.payload == nil {
		r.payload, err = r.options.SourceKeys.Open(r.owner.Purpose, Binding{Store: r.store, Object: r.owner.Object}, r.sourceCipher, int(r.owner.MaxPayloadBytes))
		if err != nil {
			return err
		}
		if r.progress != nil && !complete && (r.sourceIdentity != r.request.Source || sha256.Sum256(r.sourceCipher) != r.request.SourceCiphertext || uint64(len(r.sourceCipher)) != r.request.SourceEnvelopeBytes) {
			return errors.New("securestore: pending source changed")
		}
	}
	if !r.options.InPlace {
		dest, err := r.readOptional(r.destinationName, r.envelopeLimit())
		if err != nil {
			return err
		}
		if dest != nil {
			defer clear(dest)
			if !prepared {
				return os.ErrExist
			}
			if !complete && (sha256.Sum256(dest) != r.progress.CandidateHash || uint64(len(dest)) != r.progress.CandidateBytes) {
				return errors.New("securestore: unrelated destination blocks resume")
			}
			plain, err := r.options.NewKeys.Open(r.owner.Purpose, Binding{Store: r.store, Object: r.owner.Object}, dest, int(r.owner.MaxPayloadBytes))
			if err != nil {
				return err
			}
			clear(r.payload)
			r.payload = plain
			r.outputSelected = true
		} else if complete {
			return errors.New("securestore: completed output is missing")
		}
	}
	if r.progress == nil {
		r.request = snapshotRotationRequest{Purpose: r.owner.Purpose, InPlace: r.options.InPlace, Store: r.store, Parent: r.parent, Source: r.sourceIdentity, SourcePath: r.sourcePath, DestinationPath: r.destinationPath, SourceCiphertext: sha256.Sum256(r.sourceCipher), Payload: sha256.Sum256(r.payload), SourceRing: r.ringCommit, SourceEnvelopeBytes: uint64(len(r.sourceCipher)), PayloadBytes: uint64(len(r.payload)), Object: r.owner.Object, SourceName: r.sourceName, DestinationName: r.destinationName, SourceKeyID: r.options.SourceKeys.ActiveID(), NewKeyID: r.options.NewKeys.ActiveID()}
		if r.predecessorBootstrap != nil {
			r.request.PredecessorBootstrap = sha256.Sum256(r.predecessorBootstrap)
			r.request.PredecessorProgress = sha256.Sum256(r.predecessorProgress)
		}
		token, err := snapshotRotationToken(r.request, r.options.NewKeys)
		if err != nil {
			return err
		}
		if !r.fresh && token != r.token {
			return ErrBinding
		}
		r.token = token
		r.names = rotationNames(r.owner.Purpose, r.destinationName, r.options.NewKeys.UsageFileName(), hex.EncodeToString(r.token[:]))
		if r.fresh {
			if err := r.loadPredecessors(); err != nil {
				return err
			}
		}
	} else if !complete && (sha256.Sum256(r.payload) != r.request.Payload || uint64(len(r.payload)) != r.request.PayloadBytes) {
		return ErrBinding
	}
	if !r.fresh && r.bootstrap.Stage == snapshotRotationUninitialized && r.progressBytes != nil {
		if r.predecessorProgress == nil || !bytes.Equal(r.progressBytes, r.predecessorProgress) {
			return errors.New("securestore: encrypted progress exists before ledger-required boundary")
		}
		r.obsoleteProgress = true
	}

	// Once the selected output and its authenticated authority agree, auxiliary
	// predecessor/candidate cleanup failures cannot erase this snapshot outcome.
	if complete {
		r.result.Outcome = Committed
	} else if r.outputSelected {
		r.result.Outcome = Uncertain
	}
	if r.progress != nil {
		if err := r.loadPredecessors(); err != nil {
			return err
		}
	}
	if err := r.keyAliases(r.names[RotationCandidateStage]); err != nil {
		return err
	}
	r.candidate, err = r.readOptional(r.names[RotationCandidateStage], r.envelopeLimit())
	if err != nil {
		return err
	}
	if r.candidate != nil {
		if r.progress == nil {
			return errors.New("securestore: candidate lacks authenticated progress")
		}
		plain, err := r.options.NewKeys.Open(r.owner.Purpose, Binding{Store: r.store, Object: r.owner.Object}, r.candidate, int(r.owner.MaxPayloadBytes))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(plain)
		size := len(plain)
		clear(plain)
		if digest != r.request.Payload || uint64(size) != r.request.PayloadBytes {
			return ErrBinding
		}
		if prepared && (sha256.Sum256(r.candidate) != r.progress.CandidateHash || uint64(len(r.candidate)) != r.progress.CandidateBytes) {
			return ErrBinding
		}
	} else if prepared && !r.outputSelected {
		return errors.New("securestore: prepared candidate is missing")
	}
	if r.fresh {
		r.bootstrap = snapshotRotationBootstrap{Stage: snapshotRotationUninitialized, Purpose: r.owner.Purpose, Store: r.store, Token: r.token}
	}
	if complete {
		r.result.Outcome = Committed
	} else if r.outputSelected {
		r.result.Outcome = Uncertain
	}
	return r.step("authenticated")
}

func (r *snapshotRotation) checkRequest(q snapshotRotationRequest) error {
	if q.Purpose != r.owner.Purpose || q.Object != r.owner.Object || q.InPlace != r.options.InPlace || q.Store != r.store || q.Parent != r.parent || q.SourcePath != r.sourcePath || q.DestinationPath != r.destinationPath || q.SourceRing != r.ringCommit || q.SourceName != r.sourceName || q.DestinationName != r.destinationName || q.SourceKeyID != r.options.SourceKeys.ActiveID() || q.NewKeyID != r.options.NewKeys.ActiveID() || q.PayloadBytes > uint64(r.owner.MaxPayloadBytes) {
		return ErrBinding
	}
	return nil
}
func (r *snapshotRotation) completedReceipt(bootstrap, progress []byte, ring *Keyring, path [32]byte, name string) (snapshotRotationProgress, error) {
	b, err := parseSnapshotRotationBootstrap(bootstrap, ring)
	if err != nil {
		return snapshotRotationProgress{}, err
	}
	p, err := openSnapshotRotationProgress(progress, ring, b, path)
	if err != nil {
		return snapshotRotationProgress{}, err
	}
	if p.Stage != snapshotRotationComplete || p.Request.Store != r.store || p.Request.Purpose != r.owner.Purpose || p.Request.Object != r.owner.Object || p.Request.DestinationName != name || p.Request.NewKeyID != ring.ActiveID() || p.Request.Parent != r.parent {
		return snapshotRotationProgress{}, errors.New("securestore: source lineage is not completed")
	}
	return p, nil
}
func (r *snapshotRotation) validateSourceLineage() error {
	names := rotationNames(r.owner.Purpose, r.sourceName, "", "")
	b, err := r.readOptional(names[RotationBootstrapUninitialized], snapshotRotationBootstrapBytes)
	if err != nil {
		return err
	}
	p, err := r.readOptional(names[RotationPlanned], snapshotRotationRecordMax)
	if err != nil {
		return err
	}
	if b == nil && p == nil {
		return nil
	}
	_, err = r.completedReceipt(b, p, r.options.SourceKeys, r.sourcePath, r.sourceName)
	return err
}
func (r *snapshotRotation) loadPredecessors() error {
	expected := [2][]byte{r.predecessorBootstrap, r.predecessorProgress}
	var actual [2][]byte
	for i, s := range []RotationStage{RotationPredecessorBootstrapStage, RotationPredecessorProgressStage} {
		b, err := r.readOptional(r.names[s], snapshotRotationRecordMax)
		if err != nil {
			return err
		}
		actual[i] = b
		r.predecessorPresent[i] = b != nil
		if b != nil && expected[i] != nil && !bytes.Equal(b, expected[i]) {
			return ErrBinding
		}
	}
	if r.fresh {
		return nil
	}
	hasRequest := r.progress != nil
	hasPredecessor := actual[0] != nil || actual[1] != nil
	if hasRequest && r.request.PredecessorBootstrap == [32]byte{} {
		if hasPredecessor {
			return ErrBinding
		}
		return nil
	}
	complete := r.progress != nil && r.progress.Stage == snapshotRotationComplete
	if !hasPredecessor {
		if hasRequest && r.request.PredecessorBootstrap != [32]byte{} && !complete {
			return errors.New("securestore: required predecessor copies missing")
		}
		return nil
	}
	if actual[0] == nil || actual[1] == nil {
		if !complete {
			return errors.New("securestore: partial selected predecessor copies")
		}
	} else {
		if _, err := r.completedReceipt(actual[0], actual[1], r.options.SourceKeys, r.destinationPath, r.destinationName); err != nil {
			return err
		}
	}
	if hasRequest {
		for i, b := range actual {
			if b == nil {
				continue
			}
			want := r.request.PredecessorBootstrap
			if i == 1 {
				want = r.request.PredecessorProgress
			}
			if sha256.Sum256(b) != want {
				return ErrBinding
			}
		}
	}
	r.predecessorBootstrap, r.predecessorProgress = actual[0], actual[1]
	return nil
}

func (r *snapshotRotation) validatePayload() error {
	resident := int64(cap(r.sourceCipher)+cap(r.payload)+cap(r.candidate)+cap(r.bootstrapBytes)+cap(r.progressBytes)+cap(r.predecessorBootstrap)+cap(r.predecessorProgress)) + snapshotRotationScratchBytes
	if resident >= snapshotRotationMemoryBytes {
		return errors.New("securestore: rotation memory admission exceeded")
	}
	before := sha256.Sum256(r.payload)
	validation, err := r.owner.Validate(r.payload, r.store, snapshotRotationMemoryBytes-resident)
	if err != nil {
		return err
	}
	if sha256.Sum256(r.payload) != before {
		return errors.New("securestore: snapshot validator modified payload")
	}
	if len(validation.ProtectedPaths) > 4 {
		return errors.New("securestore: too many protected snapshot paths")
	}
	for _, path := range validation.ProtectedPaths {
		if err := r.protectPath(path); err != nil {
			return err
		}
	}
	return r.step("validated")
}
func (r *snapshotRotation) protectPath(path string) error {
	if !utf8.ValidString(path) || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return errors.New("securestore: invalid protected snapshot path")
	}
	parent, name := filepath.Split(path)
	if err := checkName(name); err != nil {
		return err
	}
	d, err := openDirectory(parent, false)
	if err != nil {
		return err
	}
	r.extraProtected = append(r.extraProtected, d)
	var st unix.Stat_t
	if err := unix.Fstat(int(d.Fd()), &st); err != nil {
		return err
	}
	parentID := FileIdentity{uint64(st.Dev), uint64(st.Ino)}
	if parentID == r.parent {
		for _, target := range append(append([]string{r.sourceName, r.options.SourceKeys.UsageFileName()}, r.names[:]...), r.destinationName) {
			if name == target {
				return errors.New("securestore: protected path aliases rotation namespace")
			}
		}
	}
	f, err := openPrivate(int(d.Fd()), name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	r.extraProtected = append(r.extraProtected, f)
	stat, err := validatePrivate(int(f.Fd()))
	if err != nil {
		return err
	}
	id := FileIdentity{uint64(stat.Dev), uint64(stat.Ino)}
	if r.options.SourceKeys.UsesFile(id) || r.options.NewKeys.UsesFile(id) {
		return errors.New("securestore: protected snapshot input aliases key")
	}
	for _, target := range append([]string{r.sourceName, r.options.SourceKeys.UsageFileName()}, r.names[:]...) {
		existing, err := r.dir.FileIdentity(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if existing == id {
			return errors.New("securestore: protected snapshot input aliases operation")
		}
	}
	r.protected = append(r.protected, id)
	return nil
}
