//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

func (r *journalRewriteOperation) retirementPlain() []byte {
	// The source commitment binds the complete request, including canonical
	// destination identity and loaded key materials, without exposing paths.
	b := append([]byte("LCJR-retired-v1\x00"), r.boot.Token[:]...)
	return append(b, r.request.Source.Digest[:]...)
}

func (r *journalRewriteOperation) prepareRetirement() error {
	var stages []securestore.RotationStage
	var proof *securestore.RotationOutputProof
	raw, err := r.sourceDir.Read(".journal-retired", rewriteMetadataBytes)
	if err == nil {
		plain, e := r.newKeys.Open(securestore.JournalState, securestore.Binding{Store: [16]byte(r.boot.Store), Object: "journal-rewrite/retired"}, raw, int(rewriteMetadataBytes))
		if e != nil {
			return e
		}
		valid := bytes.Equal(plain, r.retirementPlain())
		clear(plain)
		if !valid {
			return errRewrite
		}
		id, e := r.sourceDir.FileIdentity(".journal-retired")
		if e != nil {
			return e
		}
		proof = &securestore.RotationOutputProof{Identity: id, Bytes: int64(len(raw)), SHA256: sha256.Sum256(raw)}
	} else if errors.Is(err, os.ErrNotExist) {
		stages = []securestore.RotationStage{securestore.RotationPublication}
	} else {
		return err
	}
	config := securestore.RotationWorkspaceConfig{RotationIOConfig: securestore.RotationIOConfig{Token: hex.EncodeToString(r.boot.Token[:]), Purpose: securestore.JournalState, Destination: ".journal-retired", UsageName: r.newKeys.UsageFileName(), EnvelopeBytes: rewriteMetadataBytes, MaxWorkingBytes: r.options.MaxWorkingBytes - r.request.Plan.AllocatedBytes, DestinationIsOutput: proof != nil, Keyrings: []*securestore.Keyring{r.sourceKeys, r.newKeys}}, Stages: stages, Owners: []*securestore.Lock{r.sourceOwner, r.retireOwner, r.retireUsageOwner}, PriorOutput: proof}
	r.retireWorkspace, err = securestore.OpenRotationWorkspace(r.sourceDir, config)
	if err != nil {
		return err
	}
	if _, err := r.retireWorkspace.RecoverUnselected(); err != nil {
		return err
	}
	if err := r.retireWorkspace.Reserve(); err != nil {
		return err
	}
	if proof != nil {
		return r.retireWorkspace.SettleOutput()
	}
	return nil
}

func (r *journalRewriteOperation) publish() error {
	if !r.options.InPlace && r.retireWorkspace.SnapshotOutcome() != securestore.Committed {
		writer, err := securestore.NewWriter(r.usage)
		if err != nil {
			return err
		}
		raw, err := writer.Seal(securestore.JournalState, securestore.Binding{Store: [16]byte(r.boot.Store), Object: "journal-rewrite/retired"}, r.retirementPlain())
		if err != nil {
			return err
		}
		if err := rewriteCommitted(r.retireWorkspace.Create(securestore.RotationPublication, raw)); err != nil {
			return err
		}
		if err := r.step("retired"); err != nil {
			return err
		}
	}
	if r.outputPublished {
		if err := r.workspace.SettleOutput(); err != nil {
			return err
		}
	} else {
		var out securestore.Outcome
		var err error
		if r.options.InPlace {
			out, err = r.workspace.Replace(securestore.RotationPublication, r.candidate)
		} else {
			out, err = r.workspace.Create(securestore.RotationPublication, r.candidate)
		}
		r.result.Outcome = out
		if err := rewriteCommitted(out, err); err != nil {
			return err
		}
		r.outputPublished = true
	}
	r.result.Outcome = securestore.Committed
	if err := r.step("published"); err != nil {
		return err
	}
	r.progress.Phase = "complete"
	if err := r.saveProgress(securestore.RotationComplete); err != nil {
		return err
	}
	return r.step("complete")
}

func (r *journalRewriteOperation) finish() error {
	if err := r.usage.Close(); err != nil {
		return err
	}
	r.usage = nil
	if err := r.workspace.Close(); err != nil {
		return err
	}
	r.workspace = nil
	identity, err := r.destinationDir.FileIdentity(".segments")
	if err != nil {
		return err
	}
	proof := &securestore.RotationOutputProof{Identity: identity, Bytes: int64(len(r.candidate)), SHA256: sha256.Sum256(r.candidate), Durable: true}
	r.workspace, err = securestore.OpenRotationWorkspace(r.destinationDir, r.workspaceConfig(nil, proof))
	if err != nil {
		return err
	}
	if _, err := r.workspace.RecoverUnselected(); err != nil {
		return err
	}
	if r.retireWorkspace != nil {
		if err := r.retireWorkspace.Close(); err != nil {
			return err
		}
		r.retireWorkspace = nil
	}
	// Unused finite extent reservations remain all-zero and are never selected.
	// Remove only the exact authenticated plan names, retaining all key ledgers.
	for _, reservation := range r.reservations {
		if err := reservation.Close(); err != nil {
			return err
		}
	}
	for _, slot := range r.progress.Slots {
		name := JournalRewriteSegmentStageName(slot.ID)
		identity, err := r.destinationDir.FileIdentity(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if identity != slot.Identity {
			return errRewrite
		}
		if err := rewriteCommitted(r.destinationDir.Remove(name)); err != nil {
			return err
		}
	}
	if err := r.checkWorkingAllocation(); err != nil {
		return err
	}
	oldUsage, err := r.sourceDir.AllocatedSize(r.sourceKeys.UsageFileName())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	r.result.HistoricalUsageBytes = oldUsage
	r.result.Artifacts = []securestore.RotationArtifact{
		// Retained source directories can include ciphertext from earlier keys
		// outside the currently loaded ring; the aggregate cannot certify retirement.
		{Kind: "retained_source", KeyID: r.sourceKeys.ActiveID(), Count: 1, AllocatedBytes: r.result.OldSourceBytes, DependencyKnown: false},
		{Kind: "rewritten_journal", KeyID: r.newKeys.ActiveID(), Count: 1, AllocatedBytes: r.request.Plan.AllocatedBytes, DependencyKnown: true},
		{Kind: "usage_history", KeyID: r.sourceKeys.ActiveID(), Count: 1, AllocatedBytes: oldUsage, DependencyKnown: true},
		{Kind: "completion_receipt", KeyID: r.newKeys.ActiveID(), Count: 1, DependencyKnown: true},
	}
	if r.predecessorBootstrap != nil {
		boot, err := decodeRewriteBootstrap(r.predecessorBootstrap, r.sourceKeys)
		if err != nil {
			return err
		}
		prior, err := decodeRewriteProgress(r.predecessorProgress, r.sourceKeys, boot)
		if err != nil {
			return err
		}
		r.result.Artifacts = append(r.result.Artifacts, securestore.RotationArtifact{Kind: "predecessor_source", KeyID: prior.Request.SourceKeyID, Count: 1, DependencyKnown: false})
	}
	// Receipt remains encrypted and authenticated for an explicit identical
	// resume. The report does not authorize deleting source keys or backups.
	r.result.Complete = true
	r.result.ResumeRequired = false
	r.result.InventoryComplete = true
	return nil
}
