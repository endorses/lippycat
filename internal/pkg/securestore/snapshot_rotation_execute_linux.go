//go:build linux

package securestore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
)

func (r *snapshotRotation) stages() ([]RotationStage, int) {
	if r.progress != nil && r.progress.Stage == snapshotRotationComplete {
		return nil, 0
	}
	var stages []RotationStage
	if r.fresh {
		for i, s := range []RotationStage{RotationPredecessorBootstrapStage, RotationPredecessorProgressStage} {
			if r.predecessorBootstrap != nil && !r.predecessorPresent[i] {
				stages = append(stages, s)
			}
		}
		stages = append(stages, RotationBootstrapUninitialized)
	}
	if r.bootstrap.Stage == snapshotRotationUninitialized {
		if !r.newLedger {
			stages = append(stages, RotationUsageZero)
		}
		stages = append(stages, RotationBootstrapRequired)
	}
	seals := 0
	if r.progress == nil {
		stages = append(stages, RotationPlanned)
		seals++
	}
	if r.candidate == nil && !r.outputSelected {
		stages = append(stages, RotationCandidateStage)
		seals++
	}
	if r.progress == nil || r.progress.Stage == snapshotRotationPlanned {
		stages = append(stages, RotationPrepared)
		seals++
	}
	if !r.outputSelected {
		stages = append(stages, RotationPublication)
	}
	stages = append(stages, RotationComplete)
	seals++
	for i := 0; i < seals; i++ {
		stages = append(stages, RotationUsageReservation0+RotationStage(i))
	}
	return stages, seals
}
func (r *snapshotRotation) admitUsage(stages []RotationStage) error {
	usedSeals, usedBlocks, reservedSeals, reservedBlocks := r.newSeals, r.newBlocks, r.newSeals, r.newBlocks
	sealLimit, blockLimit := MaxKeyInvocations*9/10, MaxKeyBlocks*9/10
	for _, s := range stages {
		var object string
		var length int
		switch s {
		case RotationPlanned, RotationPrepared, RotationComplete:
			p := snapshotRotationProgress{Stage: snapshotRotationPlanned, Request: r.request}
			b, err := p.marshal()
			if err != nil {
				return err
			}
			length = len(b)
			object = snapshotRotationProgressBinding(r.store, r.destinationPath, r.token).Object
		case RotationCandidateStage:
			length = len(r.payload)
			object = r.owner.Object
		default:
			continue
		}
		header := fixedHeaderBytes + len(r.options.NewKeys.ActiveID()) + nonceBytes
		plain := bindingFixedBytes + len(object) + length
		blocks := uint64((header+15)/16 + (plain+tagBytes+15)/16 + 1)
		if usedSeals >= sealLimit || usedBlocks >= blockLimit || blocks > blockLimit-usedBlocks {
			return ErrKeyExhausted
		}
		usedSeals++
		usedBlocks += blocks
		if usedSeals > reservedSeals || usedBlocks > reservedBlocks {
			reservedSeals = max(reservedSeals, roundReservation(usedSeals, invocationReservation, sealLimit))
			reservedBlocks = max(reservedBlocks, roundReservation(usedBlocks, blockReservation, blockLimit))
		}
	}
	return nil
}
func (r *snapshotRotation) workspaceConfig(stages []RotationStage) (RotationWorkspaceConfig, error) {
	e := int64(fixedHeaderBytes+len(r.options.NewKeys.ActiveID())+nonceBytes+tagBytes+bindingFixedBytes+len(r.owner.Object)) + int64(r.request.PayloadBytes)
	cfg := RotationWorkspaceConfig{RotationIOConfig: RotationIOConfig{Token: hex.EncodeToString(r.token[:]), Purpose: r.owner.Purpose, Destination: r.destinationName, UsageName: r.options.NewKeys.UsageFileName(), EnvelopeBytes: e, MaxWorkingBytes: r.options.MaxWorkingBytes, Keyrings: []*Keyring{r.options.SourceKeys, r.options.NewKeys}, Protected: r.protected}, Stages: stages, Owners: r.locks}
	if r.outputSelected {
		b, err := r.dir.Read(r.destinationName, r.envelopeLimit())
		if err != nil {
			return cfg, err
		}
		defer clear(b)
		id, err := r.dir.FileIdentity(r.destinationName)
		if err != nil {
			return cfg, err
		}
		cfg.PriorOutput = &RotationOutputProof{Identity: id, Bytes: int64(len(b)), SHA256: sha256.Sum256(b), Durable: r.progress != nil && r.progress.Stage == snapshotRotationComplete}
		if int64(len(b)) > cfg.EnvelopeBytes {
			cfg.EnvelopeBytes = int64(len(b))
		}
	}
	return cfg, nil
}
func (r *snapshotRotation) execute() error {
	stages, seals := r.stages()
	if err := r.admitUsage(stages); err != nil {
		return err
	}
	// During sealing, the payload, old envelope, new candidate and AEAD input may
	// coexist. This is the same aggregate ceiling as the owner's decode admission.
	e := int64(fixedHeaderBytes+len(r.options.NewKeys.ActiveID())+nonceBytes+tagBytes+bindingFixedBytes+len(r.owner.Object)) + int64(len(r.payload))
	if int64(cap(r.sourceCipher)+cap(r.payload))+2*e+snapshotRotationScratchBytes > snapshotRotationMemoryBytes {
		return errors.New("securestore: rotation encryption memory admission exceeded")
	}
	cfg, err := r.workspaceConfig(stages)
	if err != nil {
		return err
	}
	r.workspace, err = OpenRotationWorkspace(r.dir, cfg)
	if err != nil {
		return err
	}
	if r.hooks != nil && r.hooks.workspace != nil {
		r.hooks.workspace(r.workspace)
	}
	temps, _, err := r.workspace.inventory()
	if err != nil {
		return err
	}
	if !r.options.Resume && len(temps) > 0 {
		return errors.New("securestore: interrupted workspace requires explicit resume")
	}
	if _, err = r.workspace.RecoverUnselected(); err != nil {
		r.updateOutcome()
		return err
	}
	r.updateOutcome()
	if err := r.step("recovered"); err != nil {
		return err
	}
	if err = r.workspace.Reserve(); err != nil {
		r.updateOutcome()
		return err
	}
	r.updateOutcome()
	if err := r.step("reserved"); err != nil {
		return err
	}
	if r.fresh {
		for i, s := range []RotationStage{RotationPredecessorBootstrapStage, RotationPredecessorProgressStage} {
			if r.predecessorBootstrap == nil || r.predecessorPresent[i] {
				continue
			}
			b := r.predecessorBootstrap
			if i == 1 {
				b = r.predecessorProgress
			}
			if err := r.publish(s, b, true); err != nil {
				return err
			}
		}
		b, err := r.bootstrap.marshal(r.options.NewKeys)
		if err != nil {
			return err
		}
		if err := r.publish(RotationBootstrapUninitialized, b, r.bootstrapBytes == nil); err != nil {
			return err
		}
		r.bootstrapBytes = b
		r.obsoleteProgress = r.predecessorProgress != nil
	}
	if r.obsoleteProgress {
		if _, err := r.dir.Remove(r.names[RotationPlanned]); err != nil {
			return err
		}
		r.progressBytes = nil
		r.obsoleteProgress = false
		if err := r.step("predecessor-progress-removed"); err != nil {
			return err
		}
	}
	if r.bootstrap.Stage == snapshotRotationUninitialized {
		if !r.newLedger {
			out, err := r.workspace.InitializeUsage(r.options.NewKeys, r.store)
			if err != nil || out != Committed {
				return errors.Join(err, errors.New("securestore: zero usage publication failed"))
			}
			r.newLedger = true
			if err := r.step("usage-zero"); err != nil {
				return err
			}
		}
		r.bootstrap.Stage = snapshotRotationRequired
		b, err := r.bootstrap.marshal(r.options.NewKeys)
		if err != nil {
			return err
		}
		if err := r.publish(RotationBootstrapRequired, b, false); err != nil {
			return err
		}
		r.bootstrapBytes = b
	}
	if seals > 0 {
		r.usage, err = r.workspace.OpenUsage(r.options.NewKeys, r.store)
		if err != nil {
			return err
		}
		if r.hooks != nil && r.hooks.step != nil {
			write := r.usage.write
			r.usage.write = func(n string, b []byte) (Outcome, error) {
				out, err := write(n, b)
				if out == Committed && err == nil {
					err = r.step("usage-reserved")
				}
				return out, err
			}
		}
	}
	writer := &Writer{usage: r.usage}
	if r.progress == nil {
		p := snapshotRotationProgress{Stage: snapshotRotationPlanned, Request: r.request}
		if err := r.writeProgress(writer, RotationPlanned, p, true); err != nil {
			return err
		}
	}
	if r.candidate == nil && !r.outputSelected {
		r.candidate, err = writer.Seal(r.owner.Purpose, Binding{Store: r.store, Object: r.owner.Object}, r.payload)
		if err != nil {
			return err
		}
		if err := r.step("candidate-sealed"); err != nil {
			return err
		}
		if err := r.publish(RotationCandidateStage, r.candidate, true); err != nil {
			return err
		}
	}
	if r.progress.Stage == snapshotRotationPlanned {
		p := snapshotRotationProgress{Stage: snapshotRotationPrepared, Request: r.request, CandidateBytes: uint64(len(r.candidate)), CandidateHash: sha256.Sum256(r.candidate)}
		if err := r.writeProgress(writer, RotationPrepared, p, false); err != nil {
			return err
		}
	}
	if !r.outputSelected {
		if err := r.publish(RotationPublication, r.candidate, !r.options.InPlace); err != nil {
			return err
		}
		r.outputSelected = true
	}
	if r.progress.Stage != snapshotRotationComplete {
		p := *r.progress
		p.Stage = snapshotRotationComplete
		if err := r.writeProgress(writer, RotationComplete, p, false); err != nil {
			return err
		}
	}
	r.result.Outcome = Committed
	if err := r.cleanup(); err != nil {
		return err
	}
	if err := r.inventoryReport(); err != nil {
		return err
	}
	r.result.Complete = true
	r.result.ResumeRequired = false
	return r.step("complete")
}
func (r *snapshotRotation) publish(s RotationStage, data []byte, create bool) error {
	var out Outcome
	var err error
	if create {
		out, err = r.workspace.Create(s, data)
	} else {
		out, err = r.workspace.Replace(s, data)
	}
	r.updateOutcome()
	if err != nil {
		return err
	}
	if out != Committed {
		return errors.New("securestore: rotation stage not committed")
	}
	return r.step(rotationStageNames[s])
}
func (r *snapshotRotation) writeProgress(writer *Writer, s RotationStage, p snapshotRotationProgress, create bool) error {
	b, err := sealSnapshotRotationProgress(p, r.options.NewKeys, writer)
	if err != nil {
		return err
	}
	if err := r.step(rotationStageNames[s] + "-sealed"); err != nil {
		return err
	}
	if err := r.publish(s, b, create); err != nil {
		return err
	}
	r.progress = &p
	r.progressBytes = b
	return nil
}
func (r *snapshotRotation) cleanup() error {
	if r.usage != nil {
		if err := r.usage.Close(); err != nil {
			return err
		}
		r.usage = nil
	}
	if err := r.workspace.Close(); err != nil {
		return err
	}
	r.workspace = nil
	cfg, err := r.workspaceConfig(nil)
	if err != nil {
		return err
	}
	r.workspace, err = OpenRotationWorkspace(r.dir, cfg)
	if err != nil {
		return err
	}
	if _, err := r.workspace.RecoverUnselected(); err != nil {
		return err
	}
	r.updateOutcome()
	if err := r.step("temporary-cleanup"); err != nil {
		return err
	}
	for _, s := range []RotationStage{RotationCandidateStage, RotationPredecessorBootstrapStage, RotationPredecessorProgressStage} {
		_, err := r.dir.FileIdentity(r.names[s])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := r.dir.Remove(r.names[s]); err != nil {
			return err
		}
		if err := r.step(rotationStageNames[s] + "-removed"); err != nil {
			return err
		}
	}
	return nil
}
