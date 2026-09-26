package filtering

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

const (
	bootstrapBytes               = 56
	bootstrapUninitialized  byte = 1
	bootstrapLedgerRequired byte = 2
)

// A bootstrap contains only a random store identity, a lifecycle stage and an
// opaque keyed commitment. Source identities/content hashes remain encrypted in
// the later intent. The required stage is committed BEFORE the first GCM seal;
// once reached, missing usage state is fatal and can never reset a used key.
type filterBootstrap struct {
	stage byte
	store [16]byte
	mac   [32]byte
}

func (b filterBootstrap) encode() []byte {
	data := make([]byte, bootstrapBytes)
	copy(data, "LCFB")
	data[4], data[5] = 1, b.stage
	copy(data[8:24], b.store[:])
	copy(data[24:], b.mac[:])
	return data
}

func (b filterBootstrap) binding(ring *securestore.Keyring, intent filterStoreIntent) ([32]byte, error) {
	context, err := json.Marshal(intent)
	if err != nil {
		return [32]byte{}, errors.New("encode filter initialization commitment")
	}
	defer clear(context)
	return ring.InitializationBinding(securestore.FilterSnapshot, append(b.encode()[:24], context...))
}

func (b filterBootstrap) verify(ring *securestore.Keyring, intent filterStoreIntent) error {
	want, err := b.binding(ring, intent)
	if err != nil {
		return err
	}
	if !hmac.Equal(want[:], b.mac[:]) {
		return errors.New("filter initialization source, content, destination, or key does not match its authenticated commitment")
	}
	return nil
}

func openFilterBootstrap(dir *securestore.Dir, name string, ring *securestore.Keyring, intent filterStoreIntent, resume, completedInPlace bool) (filterBootstrap, error) {
	var b filterBootstrap
	if !resume {
		b.stage = bootstrapUninitialized
		if _, err := rand.Read(b.store[:]); err != nil {
			return b, fmt.Errorf("generate filter store identity: %w", err)
		}
		var err error
		b.mac, err = b.binding(ring, intent)
		if err != nil {
			return b, err
		}
		_, err = dir.Create(name, b.encode())
		return b, err
	}
	data, err := dir.Read(name, bootstrapBytes)
	if err != nil {
		return b, fmt.Errorf("resume requires the original initialization commitment: %w", err)
	}
	if len(data) != bootstrapBytes || string(data[:4]) != "LCFB" || data[4] != 1 || data[6] != 0 || data[7] != 0 || data[5] != bootstrapUninitialized && data[5] != bootstrapLedgerRequired {
		return b, errors.New("invalid filter initialization commitment")
	}
	b.stage = data[5]
	copy(b.store[:], data[8:24])
	copy(b.mac[:], data[24:])
	if b.store == [16]byte{} {
		return b, errors.New("invalid filter initialization identity")
	}
	if completedInPlace {
		if b.stage != bootstrapLedgerRequired {
			return b, errors.New("encrypted output exists before the required usage boundary")
		}
		// The original plaintext is gone. Verification is deferred until the
		// already required ledger and encrypted original intent authenticate.
		return b, nil
	}
	return b, b.verify(ring, intent)
}

func (b *filterBootstrap) requireLedger(dir *securestore.Dir, name string, ring *securestore.Keyring, intent filterStoreIntent) error {
	if b.stage == bootstrapLedgerRequired {
		return nil
	}
	next := *b
	next.stage = bootstrapLedgerRequired
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
		return errors.New("filter initialization ledger boundary was not committed")
	}
	*b = next
	return nil
}

func openOfflineUsage(dir *securestore.Dir, ring *securestore.Keyring, bootstrap filterBootstrap) (*securestore.Usage, error) {
	usage, err := securestore.OpenUsage(dir, ring, bootstrap.store)
	if err == nil {
		return usage, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if bootstrap.stage != bootstrapUninitialized {
		return nil, errors.New("required encryption usage ledger is missing; it must never be recreated after sealing was enabled")
	}
	if _, err := securestore.InitializeUsage(dir, ring, bootstrap.store); err != nil {
		return nil, err
	}
	return securestore.OpenUsage(dir, ring, bootstrap.store)
}
