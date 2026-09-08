//go:build li

package delivery

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"io"
	"os"
	"path/filepath"

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
	if err := checkJournalMode(path, false); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxReplayManifestBytes+1))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(raw) > maxReplayManifestBytes {
		return fmt.Errorf("replay manifest exceeds 4 MiB")
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
func (c *Client) ExportHeldJournalManifest(path string) error {
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
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	spool, err := filepath.Abs(c.journal.cfg.Dir)
	if err != nil {
		return err
	}
	if filepath.Dir(abs) == spool {
		return fmt.Errorf("export replay manifest outside the spool directory")
	}
	f, err := os.CreateTemp(filepath.Dir(abs), ".li-replay-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
			logger.Error("Remove temporary replay manifest", "error", err)
		}
	}()
	_, writeErr := f.Write(raw)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp, abs); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(abs))
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

var errManifestBatchComplete = errors.New("manifest batch complete")
