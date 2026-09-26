//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

func rewriteCommitted(out securestore.Outcome, err error) error {
	if out == securestore.Committed && err == nil {
		return nil
	}
	if err == nil {
		err = errRewrite
	}
	return &securestore.CommitError{Outcome: out, Op: "journal rewrite metadata", Err: err}
}

func (r *journalRewriteOperation) workspaceConfig(stages []securestore.RotationStage, proof *securestore.RotationOutputProof) securestore.RotationWorkspaceConfig {
	return securestore.RotationWorkspaceConfig{RotationIOConfig: securestore.RotationIOConfig{
		Token: hex.EncodeToString(r.boot.Token[:]), Purpose: securestore.JournalState, Destination: ".segments", UsageName: r.newKeys.UsageFileName(), EnvelopeBytes: rewriteMetadataBytes,
		MaxWorkingBytes: r.options.MaxWorkingBytes - r.request.Plan.AllocatedBytes, DestinationIsOutput: proof != nil, Keyrings: []*securestore.Keyring{r.sourceKeys, r.newKeys},
	}, Stages: stages, Owners: []*securestore.Lock{r.destinationOwner, r.publicationOwner, r.usageOwner}, PriorOutput: proof}
}

func (r *journalRewriteOperation) execute() error {
	prepared := r.progress != nil && r.progress.Phase != "planned"
	var proof *securestore.RotationOutputProof
	var err error
	if prepared {
		r.candidate, err = r.destinationDir.Read(r.candidateName, rewriteMetadataBytes)
		if err != nil {
			return err
		}
		if int64(len(r.candidate)) != r.progress.CandidateBytes || sha256.Sum256(r.candidate) != r.progress.CandidateSHA256 {
			return errRewrite
		}
		current, e := r.destinationDir.Read(".segments", rewriteMetadataBytes)
		if e == nil && sha256.Sum256(current) == r.progress.CandidateSHA256 {
			identity, e := r.destinationDir.FileIdentity(".segments")
			if e != nil {
				return e
			}
			proof = &securestore.RotationOutputProof{Identity: identity, Bytes: int64(len(current)), SHA256: sha256.Sum256(current), Durable: r.progress.Phase == "complete"}
			r.outputPublished = true
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		} else if !r.options.InPlace && e == nil {
			return errRewrite
		} else if r.progress.Phase == "complete" {
			// A historical receipt is never permission to overwrite a later
			// runtime catalog. Such a store requires a new offline operation.
			return errRewrite
		} else if r.options.InPlace && (e != nil || !bytes.Equal(current, r.archive)) {
			return errRewrite
		}
	}
	if !prepared && !r.fresh {
		if err := r.cleanAttempt(); err != nil {
			return err
		}
	}
	stages := []securestore.RotationStage{securestore.RotationUsageReservation0, securestore.RotationComplete}
	if r.fresh {
		stages = append(stages, securestore.RotationBootstrapUninitialized)
	}
	if r.boot.Stage == 1 {
		stages = append(stages, securestore.RotationBootstrapRequired)
	}
	if r.newLedger {
		stages = append(stages, securestore.RotationUsageZero)
	}
	if !prepared {
		stages = append(stages, securestore.RotationPlanned, securestore.RotationPrepared, securestore.RotationCandidateStage)
	}
	if !r.outputPublished {
		stages = append(stages, securestore.RotationPublication)
	}
	archiveMissing := false
	if r.options.InPlace && r.options.SourceFormat == "segments" {
		_, e := r.destinationDir.FileIdentity(rewriteArchive(r.boot.Token))
		archiveMissing = errors.Is(e, os.ErrNotExist)
		if e != nil && !archiveMissing {
			return e
		}
		if archiveMissing {
			stages = append(stages, securestore.RotationSourceCatalogStage)
		}
	}
	var archivePredecessor []securestore.RotationStage
	if r.predecessorBootstrap != nil {
		for _, stage := range []securestore.RotationStage{securestore.RotationPredecessorBootstrapStage, securestore.RotationPredecessorProgressStage} {
			prefix := ".rotation-prev-bootstrap-"
			if stage == securestore.RotationPredecessorProgressStage {
				prefix = ".rotation-prev-progress-"
			}
			_, err := r.destinationDir.FileIdentity(prefix + hex.EncodeToString(r.boot.Token[:]))
			if errors.Is(err, os.ErrNotExist) {
				stages = append(stages, stage)
				archivePredecessor = append(archivePredecessor, stage)
			} else if err != nil {
				return err
			}
		}
	}
	r.workspace, err = securestore.OpenRotationWorkspace(r.destinationDir, r.workspaceConfig(stages, proof))
	if err != nil {
		return err
	}
	if _, err := r.workspace.RecoverUnselected(); err != nil {
		return err
	}
	if err := r.workspace.Reserve(); err != nil {
		return err
	}
	if !r.options.InPlace {
		if err := r.prepareRetirement(); err != nil {
			return err
		}
	}
	for _, stage := range archivePredecessor {
		raw := r.predecessorBootstrap
		if stage == securestore.RotationPredecessorProgressStage {
			raw = r.predecessorProgress
		}
		if err := rewriteCommitted(r.workspace.Create(stage, raw)); err != nil {
			return err
		}
	}
	if r.fresh {
		if r.predecessorBootstrap != nil {
			// The prior candidate is historical metadata, never current authority;
			// preserve its complete receipt before making room for this attempt.
			if _, e := r.destinationDir.FileIdentity(r.candidateName); e == nil {
				if err := rewriteCommitted(r.destinationDir.Remove(r.candidateName)); err != nil {
					return err
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
		b, err := r.boot.encode(r.newKeys)
		if err != nil {
			return err
		}
		var out securestore.Outcome
		if r.predecessorBootstrap != nil {
			out, err = r.workspace.Replace(securestore.RotationBootstrapUninitialized, b)
		} else {
			out, err = r.workspace.Create(securestore.RotationBootstrapUninitialized, b)
		}
		if err := rewriteCommitted(out, err); err != nil {
			return err
		}
		if err := r.step("bootstrap"); err != nil {
			return err
		}
	}
	if archiveMissing {
		if err := rewriteCommitted(r.workspace.Create(securestore.RotationSourceCatalogStage, r.archive)); err != nil {
			return err
		}
	}
	if !prepared {
		if err := r.reserveSegments(); err != nil {
			return err
		}
	}
	if err := r.checkWorkingAllocation(); err != nil {
		return err
	}
	if err := r.step("allocated"); err != nil {
		return err
	}
	if r.newLedger {
		if err := rewriteCommitted(r.workspace.InitializeUsage(r.newKeys, [16]byte(r.boot.Store))); err != nil {
			return err
		}
	}
	if r.boot.Stage == 1 {
		r.boot.Stage = 2
		b, err := r.boot.encode(r.newKeys)
		if err != nil {
			return err
		}
		if err := rewriteCommitted(r.workspace.Replace(securestore.RotationBootstrapRequired, b)); err != nil {
			return err
		}
	}
	if err := r.step("ledger-required"); err != nil {
		return err
	}
	r.usage, err = r.workspace.OpenUsageAttempt(r.newKeys, [16]byte(r.boot.Store))
	if err != nil {
		return err
	}
	seals, blocks := uint64(8), uint64(8*rewriteMetadataBytes/8)
	if !prepared {
		seals += r.request.Plan.Seals
		blocks += r.request.Plan.Blocks
	}
	if err := r.usage.ReserveAttempt(seals, blocks, func(_ string, b []byte) (securestore.Outcome, error) {
		return r.workspace.Replace(securestore.RotationUsageReservation0, b)
	}); err != nil {
		return err
	}
	if err := r.step("usage-reserved"); err != nil {
		return err
	}
	if !prepared {
		if err := r.buildCandidate(); err != nil {
			return err
		}
	}
	if err := r.verifyCandidate(); err != nil {
		return err
	}
	if err := r.publish(); err != nil {
		return err
	}
	return r.finish()
}

func (r *journalRewriteOperation) reserveSegments() error {
	attempt := uint64(1)
	if r.progress != nil {
		attempt = r.progress.Attempt + 1
	}
	p := &journalRewriteProgress{Version: 1, Request: r.request, Phase: "planned", Attempt: attempt}
	var names []string
	for i := 0; i < int(r.boot.Data)+int(r.boot.Controls); i++ {
		names = append(names, JournalRewriteSegmentName(rewriteSlotID(r.boot.Token, attempt, i)))
	}
	if err := r.acquire(r.destinationDir, names...); err != nil {
		return err
	}
	for i, name := range names {
		id := rewriteSlotID(r.boot.Token, attempt, i)
		kind := "data"
		if i >= int(r.boot.Data) {
			kind = "control"
		}
		stage := JournalRewriteSegmentStageName(id)
		reserved, err := r.destinationDir.ReserveFixedSegment(stage, name)
		if err != nil {
			return err
		}
		r.reservations = append(r.reservations, reserved)
		identity, err := r.destinationDir.FileIdentity(stage)
		if err != nil {
			return err
		}
		p.Slots = append(p.Slots, journalRewriteSlot{ID: id, Kind: kind, Identity: identity})
	}
	r.progress = p
	return nil
}

func (r *journalRewriteOperation) saveProgress(stage securestore.RotationStage) error {
	plain, err := json.Marshal(r.progress)
	if err != nil {
		return err
	}
	defer clear(plain)
	if len(plain) > int(rewriteMetadataBytes)-1024 {
		return errRewrite
	}
	w, err := securestore.NewWriter(r.usage)
	if err != nil {
		return err
	}
	encoded, err := w.Seal(securestore.JournalState, securestore.Binding{Store: [16]byte(r.boot.Store), Object: rewriteProgressObject(r.boot.Token)}, plain)
	if err != nil {
		return err
	}
	return rewriteCommitted(r.workspace.Replace(stage, encoded))
}

func (r *journalRewriteOperation) buildCandidate() error {
	if err := r.saveProgress(securestore.RotationPlanned); err != nil {
		return err
	}
	if err := r.step("planned"); err != nil {
		return err
	}
	var slots []JournalRewriteSegment
	for i, slot := range r.progress.Slots {
		reservation := r.reservations[i]
		slots = append(slots, JournalRewriteSegment{ID: slot.ID, Kind: slot.Kind, Owner: r.owner(r.destinationDir, JournalRewriteSegmentName(slot.ID)), Initialize: func(b []byte) (securestore.Outcome, error) {
			out, err := reservation.Initialize(b)
			return out, errors.Join(err, reservation.Close())
		}})
	}
	metadata := r.request.Source
	metadata.JournalUUID = r.boot.Store
	var err error
	r.target, err = OpenJournalRewriteTarget(JournalRewriteTargetOptions{Config: r.destinationConfig, Metadata: metadata, Directory: r.destinationDir, Owner: r.destinationOwner, Usage: r.usage, Segments: slots})
	if err != nil {
		return err
	}
	if err := r.source.VisitRecords(func(record JournalRecord, admission uint64) error {
		record.JournalUUID = r.boot.Store
		return r.target.ImportRecord(record, admission)
	}); err != nil {
		return err
	}
	if err := r.source.VisitControls(r.target.ImportControl); err != nil {
		return err
	}
	r.candidate, err = r.target.Finish()
	if err != nil {
		return err
	}
	if err := r.target.Close(); err != nil {
		return err
	}
	r.target = nil
	if len(r.candidate) > int(rewriteMetadataBytes) {
		return errRewrite
	}
	if err := rewriteCommitted(r.workspace.Create(securestore.RotationCandidateStage, r.candidate)); err != nil {
		return err
	}
	r.progress.Phase = "prepared"
	r.progress.CandidateBytes = int64(len(r.candidate))
	r.progress.CandidateSHA256 = sha256.Sum256(r.candidate)
	if err := r.saveProgress(securestore.RotationPrepared); err != nil {
		return err
	}
	return r.step("prepared")
}

func (r *journalRewriteOperation) verifyCandidate() error {
	// The decoder acquires exact selected segment owners itself. Release builder
	// segment locks after closing every descriptor; directory ownership persists.
	for _, slot := range r.progress.Slots {
		if owner := r.owner(r.destinationDir, JournalRewriteSegmentName(slot.ID)); owner != nil {
			if err := owner.Close(); err != nil {
				return err
			}
		}
	}
	cfg := r.destinationConfig
	cfg.rewriteUsage = r.usage
	cfg.StateIncarnation = r.request.Source.StateIncarnation
	cfg.MaxAge = r.request.Source.MaxAge
	reader, err := OpenJournalRewriteSourceCatalogOwned(cfg, "segments", r.destinationDir, r.destinationOwner, r.candidateName)
	if err != nil {
		return err
	}
	m := reader.Metadata()
	err = reader.Close()
	if m.JournalUUID != r.boot.Store || m.StateIncarnation != r.request.Source.StateIncarnation || m.RecordHighwater != r.request.Source.RecordHighwater || m.AdmissionHighwater != r.request.Source.AdmissionHighwater || m.Records != r.request.Source.Records || m.PlaintextBytes != r.request.Source.PlaintextBytes {
		return errors.Join(err, errRewrite)
	}
	return err
}

func (r *journalRewriteOperation) cleanAttempt() error {
	attempt := uint64(1)
	if r.progress != nil {
		attempt = r.progress.Attempt
	}
	for _, n := range []uint64{attempt, attempt + 1} {
		for i := 0; i < int(r.boot.Data)+int(r.boot.Controls); i++ {
			id := rewriteSlotID(r.boot.Token, n, i)
			for _, name := range []string{JournalRewriteSegmentName(id), JournalRewriteSegmentStageName(id), JournalRewriteSegmentStageName(id) + ".reserve"} {
				identity, err := r.destinationDir.FileIdentity(name)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					return err
				}
				if r.sourceKeys.UsesFile(identity) || r.newKeys.UsesFile(identity) {
					return errRewrite
				}
				if r.progress != nil && n == attempt && identity != r.progress.Slots[i].Identity {
					return errRewrite
				}
				if (r.progress == nil || n != attempt) && name == JournalRewriteSegmentName(id) {
					return errRewrite
				}
				if err := rewriteCommitted(r.destinationDir.Remove(name)); err != nil {
					return err
				}
			}
		}
	}
	// A candidate without prepared progress is only unpublished build output.
	if _, err := r.destinationDir.FileIdentity(r.candidateName); err == nil {
		return rewriteCommitted(r.destinationDir.Remove(r.candidateName))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (r *journalRewriteOperation) checkWorkingAllocation() error {
	var total int64
	for _, dir := range []*securestore.Dir{r.destinationDir, r.sourceDir} {
		if dir == r.sourceDir && r.options.InPlace && total > 0 {
			continue
		}
		err := dir.WalkEntries(func(name string) error {
			// Whole-directory measurement is conservative, including retained source
			// inodes. Every byte must fit the explicit finite working allowance.
			var n int64
			var err error
			if len(name) >= 18 && name[:18] == ".securestore-lock-" {
				n, err = dir.MetadataAllocatedSize(name)
			} else if len(name) >= 7 && name[:7] == ".usage-" {
				n, err = dir.MetadataAllocatedSize(name)
			} else if len(name) >= 19 && name[:19] == ".securestore-stage-" {
				n, err = dir.RotationTemporaryAllocatedSize(name)
			} else {
				n, err = dir.AllocatedSize(name)
			}
			if err != nil {
				return err
			}
			if n > r.options.MaxWorkingBytes-total {
				return fmt.Errorf("journal rewrite working allocation exceeds cap: %w", ErrJournalFull)
			}
			total += n
			return nil
		})
		if err != nil {
			return err
		}
	}
	r.result.WorkingAllocatedBytes = total
	return nil
}
