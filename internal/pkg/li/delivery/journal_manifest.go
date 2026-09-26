//go:build li

package delivery

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const maxReplayManifestBytes = 4 << 20

type ReplayManifest struct {
	Version int                   `json:"version"`
	Records []ReplayAuthorization `json:"records"`
}
type ReplayAuthorization struct {
	ID                    uint64    `json:"id"`
	XID                   uuid.UUID `json:"xid"`
	DID                   uuid.UUID `json:"did"`
	TaskGeneration        uint64    `json:"task_generation"`
	DestinationGeneration uint64    `json:"destination_generation"`
}

// ReplayJournalManifest combines explicit operator approval of immutable record
// identities with a current ADMF authorization check supplied by the processor.
// Neither a reused UUID nor the manifest alone is sufficient to replay product.
func (c *Client) ReplayJournalManifest(path string, authorize func(JournalRecord) bool) error {
	if authorize == nil {
		return fmt.Errorf("ADMF replay authorization callback required")
	}
	raw, err := securestore.ReadFile(path, maxReplayManifestBytes)
	if err != nil {
		return err
	}
	var manifest ReplayManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("parse replay manifest: %w", err)
	}
	if manifest.Version != 1 {
		return fmt.Errorf("unsupported replay manifest version")
	}
	records := make(map[uint64]ReplayAuthorization, len(manifest.Records))
	for _, a := range manifest.Records {
		if a.ID == 0 || a.XID == uuid.Nil || a.DID == uuid.Nil || a.TaskGeneration == 0 || a.DestinationGeneration == 0 {
			return fmt.Errorf("manifest requires full nonzero record identity")
		}
		if _, ok := records[a.ID]; ok {
			return fmt.Errorf("duplicate replay authorization %d", a.ID)
		}
		records[a.ID] = a
	}
	return c.ReplayHeldX2(func(r JournalRecord) bool {
		a, ok := records[r.ID]
		return ok && a.XID == r.XID && a.DID == r.DID && a.TaskGeneration == r.TaskGeneration && a.DestinationGeneration == r.DestinationGeneration && authorize(r)
	})
}

// ExportHeldJournalManifest writes at most 10,000 identities for operator review.
// The export is not authorization; replay still requires the explicit replay flag
// and current ADMF reconciliation. Additional records can be exported after the
// approved prefix has drained. Place the file outside the bounded spool directory.
func (c *Client) ExportHeldJournalManifest(path string) (result error) {
	if c.journal == nil {
		return fmt.Errorf("X2 journal is disabled")
	}
	manifest := ReplayManifest{Version: 1, Records: make([]ReplayAuthorization, 0)}
	err := c.journal.VisitHeld(func(r JournalRecord) error {
		if len(manifest.Records) >= 10_000 {
			return errManifestBatchComplete
		}
		manifest.Records = append(manifest.Records, ReplayAuthorization{ID: r.ID, XID: r.XID, DID: r.DID, TaskGeneration: r.TaskGeneration, DestinationGeneration: r.DestinationGeneration})
		return nil
	})
	if err != nil && !errors.Is(err, errManifestBatchComplete) {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > maxReplayManifestBytes {
		return fmt.Errorf("manifest export exceeds 4 MiB")
	}
	parentPath, name := ".", path
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		parentPath, name = path[:slash], path[slash+1:]
		if parentPath == "" {
			parentPath = "/"
		}
	}
	// Validate the uncleaned path so symlink/.. traversal cannot disappear.
	dir, err := securestore.OpenDir(parentPath)
	if err != nil {
		return err
	}
	outcome := securestore.NotCommitted
	defer func() {
		if err := dir.Close(); err != nil {
			result = errors.Join(result, &securestore.CommitError{Outcome: outcome, Op: "close manifest directory", Err: err})
		}
	}()
	same, err := c.journal.store.SameDirectory(dir)
	if err != nil {
		return err
	}
	if same {
		return fmt.Errorf("export replay manifest outside the spool directory")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return err
	}
	keyFiles := []string{c.journal.cfg.KeyFile}
	for _, ref := range c.journal.cfg.ReadKeys {
		keyFiles = append(keyFiles, ref.File)
	}
	for _, keyFile := range keyFiles {
		key, err := filepath.Abs(keyFile)
		if err != nil {
			return err
		}
		key, err = filepath.EvalSymlinks(key)
		if err != nil {
			return err
		}
		if filepath.Join(parent, name) == key {
			return fmt.Errorf("export replay manifest must not replace the journal key")
		}
	}
	lock, err := dir.Lock(name)
	if err != nil {
		return err
	}
	defer func() {
		if err := lock.Close(); err != nil {
			result = errors.Join(result, &securestore.CommitError{Outcome: outcome, Op: "close manifest lock", Err: err})
		}
	}()
	outcome, err = dir.Replace(name, raw)
	return err
}

var errManifestBatchComplete = errors.New("manifest batch complete")
