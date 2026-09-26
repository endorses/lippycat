package filtering

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

var ErrStoreFault = errors.New("managed filter store is faulted; close and reconcile before reopening")

// snapshotFile owns exactly one snapshot path for its lifetime. The backend's
// mutex serializes reads, writes and Close; the file lock excludes other owners.
type snapshotFile struct {
	path      string
	name      string
	dir       *securestore.Dir
	lock      *securestore.Lock
	validated bool
	closed    bool
	fault     error
	write     func(string, []byte) (securestore.Outcome, error)
}

func storePath(path string) (string, string, string, error) {
	if path == "" {
		return "", "", "", errors.New("managed filter store path is required")
	}
	parent, name := ".", path
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		parent, name = path[:slash], path[slash+1:]
		if parent == "" {
			parent = "/"
		}
	}
	// Preserve the raw parent for descriptor validation, including any '..'.
	abs, err := filepath.Abs(path)
	if err != nil || name == "" || name == "." || name == ".." {
		return "", "", "", errors.New("invalid managed filter snapshot path")
	}
	return parent, name, abs, nil
}

func (s *snapshotFile) open(path string, provision bool) error {
	if s.closed {
		return os.ErrClosed
	}
	if s.fault != nil {
		return errors.Join(ErrStoreFault, s.fault)
	}
	parent, name, abs, err := storePath(path)
	if err != nil {
		return err
	}
	if s.path != "" && s.path != abs {
		return errors.New("a managed persistence instance cannot switch snapshot paths")
	}
	if s.dir != nil {
		return nil
	}
	if provision {
		if err := securestore.EnsureDir(parent); err != nil {
			return fmt.Errorf("provision managed filter directory: %w", err)
		}
	}
	dir, err := securestore.OpenDir(parent)
	if err != nil {
		return fmt.Errorf("open managed filter directory: %w", err)
	}
	lock, err := dir.Lock(name)
	if err != nil {
		return errors.Join(fmt.Errorf("lock managed filter snapshot: %w", err), dir.Close())
	}
	s.path, s.name, s.dir, s.lock = abs, name, dir, lock
	s.write = dir.Replace
	return nil
}

func (s *snapshotFile) discard() error {
	var err error
	if s.lock != nil {
		err = s.lock.Close()
		s.lock = nil
	}
	if s.dir != nil {
		err = errors.Join(err, s.dir.Close())
		s.dir = nil
	}
	s.validated = false
	return err
}

func (s *snapshotFile) commit(data []byte) error {
	outcome, err := s.write(s.name, data)
	if err == nil && outcome != securestore.Committed {
		err = &securestore.CommitError{Outcome: outcome, Op: "write managed filter snapshot", Err: errors.New("snapshot was not committed")}
	}
	if outcome == securestore.Uncertain || securestore.OutcomeOf(err) == securestore.Uncertain {
		s.fault = err
	}
	return err
}

// YAMLPersistence retains editable YAML with strict whole-document loading and
// durable private writes. The first Load or Save takes lifetime ownership.
type YAMLPersistence struct {
	telemetry securestore.Telemetry
	mu        sync.Mutex
	file      snapshotFile
}

func NewYAMLPersistence() *YAMLPersistence {
	yp := &YAMLPersistence{}
	yp.telemetry.Initialize("yaml", nil)
	return yp
}

func yamlPath(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	cfg, err := ResolveStoreConfig(StoreConfig{Mode: StoreYAML}, false)
	return cfg.File, err
}

func (yp *YAMLPersistence) load(path string) (map[string]*management.Filter, error) {
	resolved, err := yamlPath(path)
	if err != nil {
		return nil, err
	}
	if err := yp.file.open(resolved, true); err != nil {
		return nil, err
	}
	data, err := yp.file.dir.Read(yp.file.name, filtercodec.MaxManagedSnapshotBytes)
	if errors.Is(err, os.ErrNotExist) {
		yp.file.validated = true
		return make(map[string]*management.Filter), nil
	}
	if err != nil {
		return nil, errors.Join(err, yp.file.discard())
	}
	filters, err := filtercodec.UnmarshalManagedYAML(data)
	if err != nil {
		return nil, errors.Join(err, yp.file.discard())
	}
	yp.file.validated = true
	return filters, nil
}

func (yp *YAMLPersistence) Load(path string) (_ map[string]*management.Filter, result error) {
	yp.mu.Lock()
	defer yp.mu.Unlock()
	defer func() {
		if result != nil {
			yp.telemetry.Fault(result)
		} else {
			yp.telemetry.Ready()
		}
	}()
	return yp.load(path)
}

func (yp *YAMLPersistence) Save(path string, filters map[string]*management.Filter) (result error) {
	yp.mu.Lock()
	defer yp.mu.Unlock()
	defer func() {
		yp.telemetry.Record(securestore.OutcomeOf(result), result)
		if yp.file.fault != nil {
			yp.telemetry.Fault(yp.file.fault)
		} else if yp.file.validated {
			yp.telemetry.Ready()
		}
	}()
	data, err := filtercodec.MarshalManagedYAML(filters)
	if err != nil {
		return err
	}
	resolved, err := yamlPath(path)
	if err != nil {
		return err
	}
	if err := yp.file.open(resolved, true); err != nil {
		return err
	}
	if !yp.file.validated {
		// Saving before Load cannot overwrite an invalid/opposite-format store.
		if _, err := yp.load(resolved); err != nil {
			return err
		}
	}
	return yp.file.commit(data)
}

func (yp *YAMLPersistence) Close() (result error) {
	yp.mu.Lock()
	defer yp.mu.Unlock()
	yp.file.closed = true
	yp.telemetry.Closing()
	defer func() { yp.telemetry.Closed(result) }()
	return yp.file.discard()
}

func (yp *YAMLPersistence) Fault() error {
	yp.mu.Lock()
	defer yp.mu.Unlock()
	return yp.file.fault
}

func (yp *YAMLPersistence) StorageStatus() securestore.StorageStatus { return yp.telemetry.Snapshot() }
