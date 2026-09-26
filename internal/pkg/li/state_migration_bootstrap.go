//go:build li

package li

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const (
	stateBootstrapBytes               = 56
	stateBootstrapUninitialized  byte = 1
	stateBootstrapLedgerRequired byte = 2
)

// A bootstrap contains only a random store identity, a lifecycle stage and an
// opaque keyed commitment. Source identities/content hashes remain encrypted in
// the later intent. The required stage is committed BEFORE the first GCM seal;
// once reached, missing usage state is fatal and can never reset a used key.
type stateBootstrap struct {
	stage byte
	store [16]byte
	mac   [32]byte
}

func (b stateBootstrap) encode() []byte {
	data := make([]byte, stateBootstrapBytes)
	copy(data, "LCSB")
	data[4], data[5] = 1, b.stage
	copy(data[8:24], b.store[:])
	copy(data[24:], b.mac[:])
	return data
}

func (b stateBootstrap) binding(ring *securestore.Keyring, intent stateMigrationIntent) ([32]byte, error) {
	context, err := json.Marshal(intent)
	if err != nil {
		return [32]byte{}, errors.New("encode LI state initialization commitment")
	}
	defer clear(context)
	return ring.InitializationBinding(securestore.AdministrativeState, append(b.encode()[:24], context...))
}

func (b stateBootstrap) verify(ring *securestore.Keyring, intent stateMigrationIntent) error {
	want, err := b.binding(ring, intent)
	if err != nil {
		return err
	}
	if !hmac.Equal(want[:], b.mac[:]) {
		return errors.New("LI state initialization source, content, destination, or key does not match its authenticated commitment")
	}
	return nil
}

// prepareStateBootstrap recovers the candidate incarnation before canonical
// serialization. A resumed bootstrap is not trusted until verify succeeds;
// callers must not open/create usage or seal anything before that verification.
func prepareStateBootstrap(dir *securestore.Dir, name string, resume bool) (stateBootstrap, error) {
	var b stateBootstrap
	if !resume {
		id, err := uuid.NewRandom()
		if err != nil {
			return b, fmt.Errorf("generate LI state identity: %w", err)
		}
		b.store, b.stage = [16]byte(id), stateBootstrapUninitialized
		return b, nil
	}
	data, err := dir.Read(name, stateBootstrapBytes)
	if err != nil {
		return b, fmt.Errorf("resume requires the original initialization commitment: %w", err)
	}
	if len(data) != stateBootstrapBytes || string(data[:4]) != "LCSB" || data[4] != 1 || data[6] != 0 || data[7] != 0 || data[5] != stateBootstrapUninitialized && data[5] != stateBootstrapLedgerRequired {
		return b, errors.New("invalid LI state initialization commitment")
	}
	b.stage = data[5]
	copy(b.store[:], data[8:24])
	copy(b.mac[:], data[24:])
	if b.store == [16]byte{} {
		return b, errors.New("invalid LI state initialization identity")
	}
	return b, nil
}

func (b *stateBootstrap) create(dir *securestore.Dir, name string, ring *securestore.Keyring, intent stateMigrationIntent) error {
	var err error
	b.mac, err = b.binding(ring, intent)
	if err != nil {
		return err
	}
	_, err = dir.Create(name, b.encode())
	return err
}

func (b *stateBootstrap) requireLedger(dir *securestore.Dir, name string, ring *securestore.Keyring, intent stateMigrationIntent) error {
	if b.stage == stateBootstrapLedgerRequired {
		return nil
	}
	next := *b
	next.stage = stateBootstrapLedgerRequired
	var err error
	next.mac, err = next.binding(ring, intent)
	if err != nil {
		return err
	}
	out, err := dir.Replace(name, next.encode())
	if err != nil {
		return err
	}
	if out != securestore.Committed {
		return errors.New("LI state initialization ledger boundary was not committed")
	}
	*b = next
	return nil
}

func openStateMigrationUsage(dir *securestore.Dir, ring *securestore.Keyring, bootstrap stateBootstrap) (*securestore.Usage, error) {
	usage, err := securestore.OpenUsage(dir, ring, bootstrap.store)
	if err == nil {
		return usage, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if bootstrap.stage != stateBootstrapUninitialized {
		return nil, errors.New("required encryption usage ledger is missing; it must never be recreated after sealing was enabled")
	}
	if _, err := securestore.InitializeUsage(dir, ring, bootstrap.store); err != nil {
		return nil, err
	}
	return securestore.OpenUsage(dir, ring, bootstrap.store)
}
