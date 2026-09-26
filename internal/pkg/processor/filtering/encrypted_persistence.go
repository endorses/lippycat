package filtering

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

const (
	filterSnapshotObject         = "filters"
	maxFilterEnvelopeBytes int64 = int64(filtercodec.MaxManagedSnapshotBytes + securestore.MaxHeaderBytes + 18 + len(filterSnapshotObject) + 16)
)

// EncryptedPersistence requires an explicitly initialized encrypted snapshot and
// usage ledger. Runtime Load/Save never initialize, migrate or guess a format.
type EncryptedPersistence struct {
	mu        sync.Mutex
	file      snapshotFile
	keys      *securestore.Keyring
	usage     *securestore.Usage
	writer    *securestore.Writer
	committed map[string]*management.Filter
}

func NewEncryptedPersistence(keys securestore.KeyConfig) (*EncryptedPersistence, error) {
	ring, err := securestore.LoadKeyring(keys)
	if err != nil {
		return nil, err
	}
	return &EncryptedPersistence{keys: ring}, nil
}

func (ep *EncryptedPersistence) discard() error {
	var err error
	if ep.usage != nil {
		err = ep.usage.Close()
		ep.usage, ep.writer = nil, nil
	}
	return errors.Join(err, ep.file.discard())
}

func (ep *EncryptedPersistence) load(path string) (map[string]*management.Filter, error) {
	if err := ep.file.open(path, false); err != nil {
		return nil, err
	}
	data, err := ep.file.dir.Read(ep.file.name, maxFilterEnvelopeBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("encrypted filter snapshot is missing; initialize or migrate it offline: %w", err)
		}
		return nil, errors.Join(err, ep.discard())
	}
	if ep.usage == nil {
		ep.usage, err = securestore.OpenUsage(ep.file.dir, ep.keys, [16]byte{})
		if err != nil {
			return nil, errors.Join(err, ep.discard())
		}
		ep.writer, err = securestore.NewWriter(ep.usage)
		if err != nil {
			return nil, errors.Join(err, ep.discard())
		}
	}
	binding := securestore.Binding{Store: ep.usage.StoreID(), Object: filterSnapshotObject}
	plain, err := ep.keys.Open(securestore.FilterSnapshot, binding, data, filtercodec.MaxManagedSnapshotBytes)
	if err != nil {
		return nil, errors.Join(err, ep.discard())
	}
	defer clear(plain)
	filters, err := filtercodec.UnmarshalEncryptedFilters(plain)
	if err != nil {
		return nil, errors.Join(err, ep.discard())
	}
	ep.file.validated = true
	ep.committed = cloneFilterMap(filters)
	return filters, nil
}

func (ep *EncryptedPersistence) Load(path string) (map[string]*management.Filter, error) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.load(path)
}

func (ep *EncryptedPersistence) Save(path string, filters map[string]*management.Filter) error {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	plain, err := filtercodec.MarshalEncryptedFilters(filters)
	if err != nil {
		return err
	}
	defer clear(plain)
	if err := ep.file.open(path, false); err != nil {
		return err
	}
	if !ep.file.validated {
		if _, err := ep.load(path); err != nil {
			return err
		}
	}
	binding := securestore.Binding{Store: ep.usage.StoreID(), Object: filterSnapshotObject}
	var data []byte
	if strictlyReducesFilters(ep.committed, filters) {
		data, err = ep.writer.SealControl(securestore.FilterSnapshot, binding, plain)
	} else {
		data, err = ep.writer.Seal(securestore.FilterSnapshot, binding, plain)
	}
	if err != nil {
		if errors.Is(err, securestore.ErrUsageFault) {
			ep.file.fault = err
		}
		return err
	}
	err = ep.file.commit(data)
	if securestore.OutcomeOf(err) == securestore.Committed {
		ep.committed = cloneFilterMap(filters)
	}
	return err
}

// Control allowance is limited to genuine reductions of the committed policy.
// Changing a selector or scope alongside disabling it is not a control-only write.
func strictlyReducesFilters(previous, candidate map[string]*management.Filter) bool {
	reduced := len(candidate) < len(previous)
	for id, filter := range candidate {
		old, exists := previous[id]
		if !exists || old == nil || filter == nil {
			return false
		}
		if proto.Equal(old, filter) {
			continue
		}
		if !old.Enabled || filter.Enabled || filter.Revision < old.Revision {
			return false
		}
		copy := proto.Clone(filter).(*management.Filter)
		copy.Enabled = true
		copy.Revision = old.Revision
		if !proto.Equal(old, copy) {
			return false
		}
		reduced = true
	}
	return reduced
}

func (ep *EncryptedPersistence) Close() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.file.closed = true
	return ep.discard()
}

func (ep *EncryptedPersistence) Fault() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.file.fault
}

func (ep *EncryptedPersistence) StoreID() [16]byte {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.usage == nil {
		return [16]byte{}
	}
	return ep.usage.StoreID()
}
