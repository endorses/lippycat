//go:build li && linux

package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

type journalRewriteHooks struct{ step func(string) error }
type rewriteHeldLock struct {
	dir         *securestore.Dir
	name, order string
	lock        *securestore.Lock
}
type journalRewriteOperation struct {
	sourceConfig, destinationConfig                                                            JournalConfig
	options                                                                                    JournalRewriteOptions
	hooks                                                                                      *journalRewriteHooks
	sourceKeys, newKeys                                                                        *securestore.Keyring
	sourceDir, destinationDir                                                                  *securestore.Dir
	sourceOwner, destinationOwner, publicationOwner, usageOwner, retireOwner, retireUsageOwner *securestore.Lock
	held                                                                                       []*rewriteHeldLock
	source                                                                                     *JournalRewriteSource
	request                                                                                    journalRewriteRequest
	boot                                                                                       journalRewriteBootstrap
	progress                                                                                   *journalRewriteProgress
	workspace, retireWorkspace                                                                 *securestore.RotationWorkspace
	usage                                                                                      *securestore.Usage
	target                                                                                     *JournalRewriteTarget
	reservations                                                                               []*securestore.FixedSegmentReservation
	candidate                                                                                  []byte
	archive                                                                                    []byte
	predecessorBootstrap, predecessorProgress                                                  []byte
	bootstrapName, progressName, candidateName                                                 string
	newLedger, fresh, outputPublished                                                          bool
	result                                                                                     JournalRewriteResult
}

func rewriteJournal(source, destination JournalConfig, options JournalRewriteOptions) (JournalRewriteResult, error) {
	return rewriteJournalWithHooks(source, destination, options, nil)
}

func rewriteJournalWithHooks(source, destination JournalConfig, options JournalRewriteOptions, hooks *journalRewriteHooks) (report JournalRewriteResult, result error) {
	r := &journalRewriteOperation{sourceConfig: source, destinationConfig: destination, options: options, hooks: hooks, result: JournalRewriteResult{Outcome: securestore.NotCommitted, ExternalBackupsExcluded: true}}
	defer func() {
		if r.workspace != nil {
			out := r.workspace.SnapshotOutcome()
			if out == securestore.Committed || out == securestore.Uncertain && r.result.Outcome != securestore.Committed {
				r.result.Outcome = out
			}
		}
		if r.target != nil {
			result = errors.Join(result, r.target.Close())
		}
		for _, reserved := range r.reservations {
			result = errors.Join(result, reserved.Close())
		}
		if r.usage != nil {
			result = errors.Join(result, r.usage.Close())
		}
		if r.workspace != nil {
			result = errors.Join(result, r.workspace.Close())
		}
		if r.retireWorkspace != nil {
			result = errors.Join(result, r.retireWorkspace.Close())
		}
		if r.source != nil {
			result = errors.Join(result, r.source.Close())
		}
		for i := len(r.held) - 1; i >= 0; i-- {
			result = errors.Join(result, r.held[i].lock.Close())
		}
		if r.destinationDir != nil && r.destinationDir != r.sourceDir {
			result = errors.Join(result, r.destinationDir.Close())
		}
		if r.sourceDir != nil {
			result = errors.Join(result, r.sourceDir.Close())
		}
		clear(r.candidate)
		clear(r.archive)
		if result != nil {
			r.result.Complete = false
			r.result.ResumeRequired = r.boot.Store != uuid.Nil
			result = &securestore.CommitError{Outcome: r.result.Outcome, Op: "rewrite journal", Err: result}
		}
		report = r.result
	}()
	if err := r.prepare(); err != nil {
		return r.result, err
	}
	if err := r.execute(); err != nil {
		return r.result, err
	}
	return r.result, nil
}

func (r *journalRewriteOperation) step(name string) error {
	if r.hooks != nil && r.hooks.step != nil {
		return r.hooks.step(name)
	}
	return nil
}

func rewriteLoadKeys(cfg JournalConfig) (*securestore.Keyring, error) {
	if cfg.Keys != nil {
		return cfg.Keys, nil
	}
	if cfg.KeyID == "" || cfg.KeyFile == "" {
		return nil, errRewrite
	}
	return securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: cfg.KeyID, File: cfg.KeyFile}, Prior: cfg.ReadKeys, LegacyID: cfg.LegacyKeyID})
}

func (r *journalRewriteOperation) acquire(dir *securestore.Dir, names ...string) error {
	var pending []*rewriteHeldLock
	for _, name := range names {
		order, err := dir.LockOrderKey(name)
		if err != nil {
			return err
		}
		pending = append(pending, &rewriteHeldLock{dir: dir, name: name, order: order})
	}
	return r.acquireSet(pending)
}
func (r *journalRewriteOperation) acquireSet(pending []*rewriteHeldLock) error {
	sort.Slice(pending, func(i, j int) bool { return pending[i].order < pending[j].order })
	for _, item := range pending {
		found := false
		for _, held := range r.held {
			if held.order == item.order {
				found = true
				break
			}
		}
		if found {
			continue
		}
		lock, err := item.dir.Lock(item.name)
		if err != nil {
			return err
		}
		item.lock = lock
		r.held = append(r.held, item)
	}
	return nil
}
func (r *journalRewriteOperation) owner(dir *securestore.Dir, name string) *securestore.Lock {
	for _, held := range r.held {
		if held.dir == dir && held.name == name {
			return held.lock
		}
	}
	return nil
}

func (r *journalRewriteOperation) prepare() error {
	s, d, o := r.sourceConfig, r.destinationConfig, r.options
	if s.Dir == "" || d.Dir == "" || (s.Interface != PDUTypeX2 && s.Interface != PDUTypeX3) || s.Interface != d.Interface || d.MaxBytes < journalSegmentMinimum || o.MaxWorkingBytes <= 0 || o.SourceFormat != "segments" && o.SourceFormat != "lcx2" && o.SourceFormat != "per-record" || s.Interface == PDUTypeX3 && o.SourceFormat != "segments" {
		return errRewrite
	}
	var err error
	r.sourceKeys, err = rewriteLoadKeys(s)
	if err != nil {
		return err
	}
	r.newKeys, err = rewriteLoadKeys(d)
	if err != nil {
		return err
	}
	ringBinding, err := r.newKeys.SourceRingBinding(r.sourceKeys)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		validate func(*securestore.Keyring) error
		ring     *securestore.Keyring
	}{{s.ValidateKeys, r.sourceKeys}, {d.ValidateKeys, r.newKeys}} {
		if entry.validate != nil {
			if err := entry.validate(entry.ring); err != nil {
				return err
			}
		}
	}
	r.result.SourceKeyID, r.result.NewKeyID = r.sourceKeys.ActiveID(), r.newKeys.ActiveID()
	s.Keys, d.Keys = r.sourceKeys, r.newKeys
	s.ValidateKeys, d.ValidateKeys = nil, nil
	r.sourceConfig, r.destinationConfig = s, d
	r.sourceDir, err = securestore.OpenDir(s.Dir)
	if err != nil {
		return err
	}
	if err := securestore.EnsureDir(d.Dir); err != nil {
		return err
	}
	r.destinationDir, err = securestore.OpenDir(d.Dir)
	if err != nil {
		return err
	}
	same, err := r.sourceDir.SameDirectory(r.destinationDir)
	if err != nil {
		return err
	}
	if same != o.InPlace {
		return errors.New("journal directory identity requires matching explicit in-place mode")
	}
	if same {
		if err := r.destinationDir.Close(); err != nil {
			return err
		}
		r.destinationDir = r.sourceDir
	}
	var roots []*rewriteHeldLock
	for _, dir := range []*securestore.Dir{r.sourceDir, r.destinationDir} {
		order, err := dir.LockOrderKey(".lock")
		if err != nil {
			return err
		}
		roots = append(roots, &rewriteHeldLock{dir: dir, name: ".lock", order: order})
	}
	if err := r.acquireSet(roots); err != nil {
		return err
	}
	r.sourceOwner, r.destinationOwner = r.owner(r.sourceDir, ".lock"), r.owner(r.destinationDir, ".lock")
	r.bootstrapName, r.progressName, r.candidateName = rewriteNames()
	bootstrap, err := r.destinationDir.Read(r.bootstrapName, 92)
	if err == nil {
		if err := r.loadLineage(bootstrap); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		if o.Resume {
			return errors.New("no authenticated journal rewrite to resume")
		}
		if _, e := r.destinationDir.FileIdentity(r.progressName); e == nil {
			return errRewrite
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		r.fresh = true
		if !same {
			if err := r.destinationDir.WalkEntries(func(name string) error {
				if name == rewriteLockName(".lock") {
					return nil
				}
				return errors.New("journal rewrite destination is not empty")
			}); err != nil {
				return err
			}
		}
	}
	if r.boot.Store != uuid.Nil {
		// Authenticated header/plan identifies the only coordinator artifacts the
		// strict legacy reader may exclude; none is source product authority.
		s.rewriteExclusions, err = r.sourceExclusions()
		if err != nil {
			return err
		}
	}
	catalog := ".segments"
	if same && o.SourceFormat == "segments" && r.boot.Store != uuid.Nil {
		if archived, e := r.sourceDir.Read(rewriteArchive(r.boot.Token), rewriteMetadataBytes); e == nil {
			catalog = rewriteArchive(r.boot.Token)
			r.archive = archived
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	r.source, err = OpenJournalRewriteSourceCatalogOwned(s, o.SourceFormat, r.sourceDir, r.sourceOwner, catalog)
	if err != nil {
		return err
	}
	metadata := r.source.Metadata()
	if !same {
		if err := r.validateSourceLineage(); err != nil {
			return err
		}
	}
	r.result.OldSourceBytes = metadata.AllocatedBytes
	// Allocation includes coordinator artifacts on resume; it is diagnostic,
	// never immutable source identity. Ciphertext digest and durable leases bind it.
	metadata.AllocatedBytes = 0
	plan, err := r.source.Plan(r.newKeys)
	if err != nil {
		return err
	}
	if plan.AllocatedBytes > o.MaxWorkingBytes || plan.AllocatedBytes > d.MaxBytes-journalSegmentScratch {
		return ErrJournalFull
	}
	store := metadata.JournalUUID
	if r.boot.Store != uuid.Nil {
		if store != uuid.Nil && store != r.boot.Store {
			return errRewrite
		}
		store = r.boot.Store
	} else if store == uuid.Nil {
		store, err = uuid.NewRandom()
		if err != nil {
			return err
		}
	}
	sourceOrder, _ := r.sourceDir.LockOrderKey(".lock")
	destinationOrder, _ := r.destinationDir.LockOrderKey(".lock")
	sourcePath, err := filepath.Abs(s.Dir)
	if err != nil {
		return err
	}
	destinationPath, err := filepath.Abs(d.Dir)
	if err != nil {
		return err
	}
	r.request = journalRewriteRequest{Version: 1, SourceDirectory: sourceOrder, DestinationDirectory: destinationOrder, SourcePath: sha256.Sum256([]byte(sourcePath)), DestinationPath: sha256.Sum256([]byte(destinationPath)), SourceRing: ringBinding, Source: metadata, OutputUUID: store, SourceKeyID: r.sourceKeys.ActiveID(), NewKeyID: r.newKeys.ActiveID(), InPlace: same, MaxBytes: d.MaxBytes, MaxWorkingBytes: o.MaxWorkingBytes, Plan: plan}
	token, err := rewriteRequestToken(r.request, r.newKeys)
	if err != nil {
		return err
	}
	if r.fresh {
		r.boot = journalRewriteBootstrap{Stage: 1, Store: store, Token: token, Data: uint16(plan.DataSegments), Controls: uint16(plan.ControlSegments)}
	} else if token != r.boot.Token || r.progress != nil && !sameRewriteRequest(r.progress.Request, r.request) {
		return errRewrite
	}
	if same && o.SourceFormat == "segments" && r.archive == nil {
		r.archive, err = r.sourceDir.Read(".segments", rewriteMetadataBytes)
		if err != nil {
			return err
		}
	}
	if err := r.authenticateUsage(); err != nil {
		return err
	}
	if err := r.acquire(r.destinationDir, ".segments", r.newKeys.UsageFileName()); err != nil {
		return err
	}
	r.publicationOwner, r.usageOwner = r.owner(r.destinationDir, ".segments"), r.owner(r.destinationDir, r.newKeys.UsageFileName())
	if !same {
		if err := r.acquire(r.sourceDir, ".journal-retired", r.newKeys.UsageFileName()); err != nil {
			return err
		}
		r.retireOwner, r.retireUsageOwner = r.owner(r.sourceDir, ".journal-retired"), r.owner(r.sourceDir, r.newKeys.UsageFileName())
	}
	return r.step("authenticated")
}

func (r *journalRewriteOperation) authenticateUsage() error {
	_, err := r.destinationDir.FileIdentity(r.newKeys.UsageFileName())
	if errors.Is(err, os.ErrNotExist) {
		if r.boot.Stage == 2 {
			return errors.New("required rewrite nonce ledger is missing")
		}
		r.newLedger = true
		return nil
	}
	if err != nil {
		return err
	}
	if r.fresh {
		return errors.New("fresh rewrite key already has usage history")
	}
	u, err := securestore.OpenUsage(r.destinationDir, r.newKeys, [16]byte(r.boot.Store))
	if err != nil {
		return err
	}
	stats := u.Stats()
	err = u.Close()
	if err != nil {
		return err
	}
	if r.boot.Stage == 1 && (stats.Invocations != 0 || stats.Blocks != 0) {
		return errors.New("uninitialized rewrite has consumed usage history")
	}
	return nil
}

func (r *journalRewriteOperation) sourceExclusions() (map[string]bool, error) {
	excluded := map[string]bool{}
	for _, name := range []string{r.bootstrapName, r.progressName, r.candidateName, rewriteArchive(r.boot.Token), ".rotation-prev-bootstrap-" + hex.EncodeToString(r.boot.Token[:]), ".rotation-prev-progress-" + hex.EncodeToString(r.boot.Token[:]), ".segments", ".journal-retired", r.newKeys.UsageFileName()} {
		excluded[name] = true
		excluded[rewriteLockName(name)] = true
	}
	attempt := uint64(1)
	if r.progress != nil {
		attempt = r.progress.Attempt
	}
	for _, n := range []uint64{attempt, attempt + 1} {
		for i := 0; i < int(r.boot.Data)+int(r.boot.Controls); i++ {
			id := rewriteSlotID(r.boot.Token, n, i)
			for _, name := range []string{JournalRewriteSegmentName(id), JournalRewriteSegmentStageName(id), JournalRewriteSegmentStageName(id) + ".reserve"} {
				excluded[name] = true
				excluded[rewriteLockName(name)] = true
			}
		}
	}
	prefix := ".securestore-stage-" + hex.EncodeToString(r.boot.Token[:]) + "-"
	err := r.sourceDir.WalkEntries(func(name string) error {
		if strings.HasPrefix(name, prefix) {
			excluded[name] = true
		}
		return nil
	})
	return excluded, err
}
