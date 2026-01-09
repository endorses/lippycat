//go:build cli || hunter || processor || tap || all

package keylog

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeClientRandom(b byte) [32]byte {
	var cr [32]byte
	for i := range cr {
		cr[i] = b
	}
	return cr
}

func makeEntry(label LabelType, cr [32]byte) *KeyEntry {
	secretLen := 32
	if label == LabelClientRandom {
		secretLen = 48
	}
	return &KeyEntry{
		Label:        label,
		ClientRandom: cr,
		Secret:       make([]byte, secretLen),
	}
}

func TestStoreBasicOperations(t *testing.T) {
	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour // Disable cleanup for tests
	store := NewStore(config)
	defer store.Stop()

	t.Run("add and get", func(t *testing.T) {
		cr := makeClientRandom(0x01)
		entry := makeEntry(LabelClientRandom, cr)

		isNew := store.Add(entry)
		assert.True(t, isNew)

		keys := store.Get(cr)
		require.NotNil(t, keys)
		assert.Equal(t, cr, keys.ClientRandom)
		assert.Equal(t, 48, len(keys.PreMasterSecret))
	})

	t.Run("add duplicate returns false", func(t *testing.T) {
		cr := makeClientRandom(0x02)
		entry := makeEntry(LabelClientRandom, cr)

		store.Add(entry)
		isNew := store.Add(entry)
		assert.False(t, isNew)
	})

	t.Run("get non-existent returns nil", func(t *testing.T) {
		cr := makeClientRandom(0xff)
		keys := store.Get(cr)
		assert.Nil(t, keys)
	})

	t.Run("has", func(t *testing.T) {
		cr := makeClientRandom(0x03)
		assert.False(t, store.Has(cr))

		store.Add(makeEntry(LabelClientRandom, cr))
		assert.True(t, store.Has(cr))
	})

	t.Run("delete", func(t *testing.T) {
		cr := makeClientRandom(0x04)
		store.Add(makeEntry(LabelClientRandom, cr))

		deleted := store.Delete(cr)
		assert.True(t, deleted)
		assert.False(t, store.Has(cr))

		deleted = store.Delete(cr)
		assert.False(t, deleted)
	})

	t.Run("clear", func(t *testing.T) {
		cr := makeClientRandom(0x05)
		store.Add(makeEntry(LabelClientRandom, cr))

		store.Clear()
		assert.Equal(t, 0, store.Size())
	})
}

func TestStoreByHex(t *testing.T) {
	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour
	store := NewStore(config)
	defer store.Stop()

	cr := makeClientRandom(0xab)
	store.Add(makeEntry(LabelClientRandom, cr))

	crHex := hex.EncodeToString(cr[:])

	t.Run("GetByHex", func(t *testing.T) {
		keys := store.GetByHex(crHex)
		require.NotNil(t, keys)
		assert.Equal(t, cr, keys.ClientRandom)
	})

	t.Run("GetByHex invalid hex", func(t *testing.T) {
		keys := store.GetByHex("invalid")
		assert.Nil(t, keys)
	})

	t.Run("GetByHex wrong length", func(t *testing.T) {
		keys := store.GetByHex("aabb")
		assert.Nil(t, keys)
	})

	t.Run("HasByHex", func(t *testing.T) {
		assert.True(t, store.HasByHex(crHex))
		assert.False(t, store.HasByHex("0000000000000000000000000000000000000000000000000000000000000000"))
		assert.False(t, store.HasByHex("invalid"))
	})
}

func TestStoreMultipleKeys(t *testing.T) {
	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour
	store := NewStore(config)
	defer store.Stop()

	cr := makeClientRandom(0x10)

	// Add multiple TLS 1.3 keys for the same session
	store.Add(&KeyEntry{
		Label:        LabelClientHandshakeTrafficSecret,
		ClientRandom: cr,
		Secret:       make([]byte, 32),
	})
	store.Add(&KeyEntry{
		Label:        LabelServerHandshakeTrafficSecret,
		ClientRandom: cr,
		Secret:       make([]byte, 32),
	})
	store.Add(&KeyEntry{
		Label:        LabelClientTrafficSecret0,
		ClientRandom: cr,
		Secret:       make([]byte, 32),
	})
	store.Add(&KeyEntry{
		Label:        LabelServerTrafficSecret0,
		ClientRandom: cr,
		Secret:       make([]byte, 32),
	})

	keys := store.Get(cr)
	require.NotNil(t, keys)

	assert.True(t, keys.IsTLS13())
	assert.False(t, keys.IsTLS12())
	assert.True(t, keys.HasDecryptionKeys())

	assert.Equal(t, 32, len(keys.ClientHandshakeTrafficSecret))
	assert.Equal(t, 32, len(keys.ServerHandshakeTrafficSecret))
	assert.Equal(t, 32, len(keys.ClientTrafficSecret0))
	assert.Equal(t, 32, len(keys.ServerTrafficSecret0))
}

func TestStoreAddMultiple(t *testing.T) {
	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour
	store := NewStore(config)
	defer store.Stop()

	entries := []*KeyEntry{
		makeEntry(LabelClientRandom, makeClientRandom(0x20)),
		makeEntry(LabelClientRandom, makeClientRandom(0x21)),
		makeEntry(LabelClientRandom, makeClientRandom(0x22)),
	}

	added := store.AddMultiple(entries)
	assert.Equal(t, 3, added)
	assert.Equal(t, 3, store.Size())
}

func TestStoreEviction(t *testing.T) {
	config := DefaultStoreConfig()
	config.MaxSessions = 3
	config.CleanupInterval = 1 * time.Hour
	store := NewStore(config)
	defer store.Stop()

	// Add 3 sessions
	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x01)))
	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x02)))
	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x03)))
	assert.Equal(t, 3, store.Size())

	// Add 4th - should evict oldest
	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x04)))
	assert.Equal(t, 3, store.Size())

	// First session should be evicted
	assert.False(t, store.Has(makeClientRandom(0x01)))
	assert.True(t, store.Has(makeClientRandom(0x04)))
}

func TestStoreStats(t *testing.T) {
	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour
	store := NewStore(config)
	defer store.Stop()

	// Add TLS 1.2 session
	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x01)))

	// Add complete TLS 1.3 session
	cr := makeClientRandom(0x02)
	store.Add(&KeyEntry{Label: LabelClientTrafficSecret0, ClientRandom: cr, Secret: make([]byte, 32)})
	store.Add(&KeyEntry{Label: LabelServerTrafficSecret0, ClientRandom: cr, Secret: make([]byte, 32)})

	// Add incomplete TLS 1.3 session
	store.Add(&KeyEntry{Label: LabelClientTrafficSecret0, ClientRandom: makeClientRandom(0x03), Secret: make([]byte, 32)})

	// Do some lookups
	store.Get(makeClientRandom(0x01)) // Hit
	store.Get(makeClientRandom(0x02)) // Hit
	store.Get(makeClientRandom(0xff)) // Miss

	stats := store.Stats()
	assert.Equal(t, 3, stats.TotalSessions)
	assert.Equal(t, 1, stats.TLS12Sessions)
	assert.Equal(t, 2, stats.TLS13Sessions)
	assert.Equal(t, 2, stats.CompleteSessions)
	assert.Equal(t, uint64(3), stats.TotalLookups)
	assert.Equal(t, uint64(2), stats.TotalHits)
	assert.InDelta(t, 0.666, stats.HitRate(), 0.01)
}

func TestStoreCleanup(t *testing.T) {
	config := DefaultStoreConfig()
	config.SessionTTL = 50 * time.Millisecond
	config.CleanupInterval = 10 * time.Millisecond
	store := NewStore(config)
	defer store.Stop()

	cr := makeClientRandom(0x01)
	store.Add(makeEntry(LabelClientRandom, cr))
	assert.Equal(t, 1, store.Size())

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, store.Size())
}

func TestStoreCallback(t *testing.T) {
	var callbackCalled bool
	var callbackCR [32]byte
	var mu sync.Mutex

	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour
	config.OnKeyAdded = func(cr [32]byte, entry *KeyEntry) {
		mu.Lock()
		callbackCalled = true
		callbackCR = cr
		mu.Unlock()
	}
	store := NewStore(config)
	defer store.Stop()

	cr := makeClientRandom(0x50)
	store.Add(makeEntry(LabelClientRandom, cr))

	// Wait for async callback
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	assert.True(t, callbackCalled)
	assert.Equal(t, cr, callbackCR)
	mu.Unlock()
}

func TestStoreForEach(t *testing.T) {
	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour
	store := NewStore(config)
	defer store.Stop()

	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x01)))
	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x02)))
	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x03)))

	var count int
	store.ForEach(func(keys *SessionKeys) bool {
		count++
		return true
	})
	assert.Equal(t, 3, count)

	// Test early termination
	count = 0
	store.ForEach(func(keys *SessionKeys) bool {
		count++
		return count < 2
	})
	assert.Equal(t, 2, count)
}

func TestStoreAllSessions(t *testing.T) {
	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour
	store := NewStore(config)
	defer store.Stop()

	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x01)))
	store.Add(makeEntry(LabelClientRandom, makeClientRandom(0x02)))

	sessions := store.AllSessions()
	assert.Len(t, sessions, 2)
}

func TestStoreConcurrency(t *testing.T) {
	config := DefaultStoreConfig()
	config.CleanupInterval = 1 * time.Hour
	store := NewStore(config)
	defer store.Stop()

	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.Add(makeEntry(LabelClientRandom, makeClientRandom(byte(i))))
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.Get(makeClientRandom(byte(i)))
		}(i)
	}

	wg.Wait()

	// All 100 entries should be present
	assert.Equal(t, 100, store.Size())
}
