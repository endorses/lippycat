package filtering

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func initializeBoundaryState(t *testing.T, path string, keys securestore.KeyConfig, stage int) [16]byte {
	t.Helper()
	dir, err := securestore.OpenDir(filepath.Dir(path))
	require.NoError(t, err)
	defer func() { require.NoError(t, dir.Close()) }()
	lock, err := dir.Lock(filepath.Base(path))
	require.NoError(t, err)
	defer func() { require.NoError(t, lock.Close()) }()
	ring, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	plain, err := filtercodec.MarshalEncryptedFilters(nil)
	require.NoError(t, err)
	intent := filterStoreIntent{Version: 1, Operation: "initialize", SourcePath: digestString(nil), TargetPath: digestString([]byte(path)), SourceContent: digestString(nil), Payload: digestString(plain), KeyID: ring.ActiveID()}
	bootstrapName := ".filter-bootstrap-" + digestString([]byte(filepath.Base(path)))
	bootstrap, err := openFilterBootstrap(dir, bootstrapName, ring, intent, false, false)
	require.NoError(t, err)
	if stage == 0 {
		return bootstrap.store
	}
	usage, err := openOfflineUsage(dir, ring, bootstrap)
	require.NoError(t, err)
	defer func() { require.NoError(t, usage.Close()) }()
	if stage == 1 {
		return bootstrap.store
	}
	require.NoError(t, bootstrap.requireLedger(dir, bootstrapName, ring, intent))
	if stage == 2 {
		return bootstrap.store
	}
	writer, err := securestore.NewWriter(usage)
	require.NoError(t, err)
	intentData, err := json.Marshal(intent)
	require.NoError(t, err)
	binding := securestore.Binding{Store: bootstrap.store, Object: "filters/offline-intent/" + digestString([]byte(filepath.Base(path)))}
	encoded, err := writer.Seal(securestore.FilterSnapshot, binding, intentData)
	require.NoError(t, err)
	if stage == 3 {
		return bootstrap.store
	}
	_, err = dir.Create(".filter-intent-"+digestString([]byte(filepath.Base(path))), encoded)
	require.NoError(t, err)
	return bootstrap.store
}

func TestOfflineBootstrapResumesEveryDurableBoundary(t *testing.T) {
	for stage, name := range []string{"commitment", "zero-ledger", "required-ledger", "seal-before-intent", "published-intent"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateStoreTestDir(t), "filters.enc")
			keys := storeTestKey(t, 92)
			identity := initializeBoundaryState(t, path, keys, stage)
			out, err := InitializeEncryptedFilterStore(path, keys, OfflineOptions{Resume: true})
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			p, err := NewEncryptedPersistence(keys)
			require.NoError(t, err)
			defer func() { require.NoError(t, p.Close()) }()
			filters, err := p.Load(path)
			require.NoError(t, err)
			require.Empty(t, filters)
			require.Equal(t, identity, p.StoreID())
			if stage >= 3 {
				require.GreaterOrEqual(t, p.usage.Stats().Invocations, uint64(8192), "already reserved usage cannot be reset during resume")
			}
		})
	}
}

func TestOfflineBootstrapNeverRecreatesRequiredLedger(t *testing.T) {
	for _, stage := range []int{2, 3, 4} {
		path := filepath.Join(privateStoreTestDir(t), "filters.enc")
		keys := storeTestKey(t, 93)
		initializeBoundaryState(t, path, keys, stage)
		ledgers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".usage-*"))
		require.NoError(t, err)
		require.Len(t, ledgers, 1)
		require.NoError(t, os.Remove(ledgers[0]))
		out, err := InitializeEncryptedFilterStore(path, keys, OfflineOptions{Resume: true})
		require.ErrorContains(t, err, "must never be recreated")
		require.Equal(t, securestore.NotCommitted, out)
		_, err = os.Stat(ledgers[0])
		require.ErrorIs(t, err, os.ErrNotExist)
		_, err = os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}

func TestOfflineBootstrapRejectsStageTamperAndChangedCommand(t *testing.T) {
	path := filepath.Join(privateStoreTestDir(t), "filters.enc")
	keys := storeTestKey(t, 94)
	initializeBoundaryState(t, path, keys, 2)
	bootstraps, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".filter-bootstrap-*"))
	require.NoError(t, err)
	require.Len(t, bootstraps, 1)
	data, err := os.ReadFile(bootstraps[0])
	require.NoError(t, err)
	data[5] = bootstrapUninitialized
	require.NoError(t, os.WriteFile(bootstraps[0], data, 0600))
	_, err = InitializeEncryptedFilterStore(path, keys, OfflineOptions{Resume: true})
	require.ErrorContains(t, err, "authenticated commitment")
}
