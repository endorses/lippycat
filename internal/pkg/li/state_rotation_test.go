//go:build li && linux

package li

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func writeStateRotationSource(t *testing.T, path string, keys securestore.KeyConfig, store [16]byte, payload []byte) {
	t.Helper()
	ring, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	dir, err := securestore.OpenDir(filepath.Dir(path))
	require.NoError(t, err)
	_, err = securestore.InitializeUsage(dir, ring, store)
	require.NoError(t, err)
	usage, err := securestore.OpenUsage(dir, ring, store)
	require.NoError(t, err)
	writer, err := securestore.NewWriter(usage)
	require.NoError(t, err)
	sealed, err := writer.Seal(securestore.AdministrativeState, securestore.Binding{Store: store, Object: stateSnapshotObject}, payload)
	require.NoError(t, err)
	_, err = dir.Create(filepath.Base(path), sealed)
	require.NoError(t, err)
	require.NoError(t, usage.Close())
	require.NoError(t, dir.Close())
}

func newStateRotationKey(t *testing.T, source string) securestore.KeyConfig {
	t.Helper()
	path := filepath.Join(filepath.Dir(source), "next-key")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{0x44}, 32), 0600))
	return securestore.KeyConfig{Active: securestore.KeyRef{ID: "state-v2", File: path}}
}

func richStateRotationPayload(t *testing.T, pin string) (*StateSnapshot, []byte) {
	t.Helper()
	s, intent := stateIntentFixture(t, StateTaskModify)
	s.RADIUSCorrelationStateFile = pin
	r := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: s.Incarnation,
		Scope: StateRevokeTask, XID: intent.XID, TaskGeneration: statePtr(intent.PreviousGeneration),
		CoveredRecordHighwater: 71, CoveredAdmissionHighwater: 90, RevokedAt: NewStateTimestamp(s.WrittenAt)}
	s.Revocations, intent.RevocationIDs = []*StateRevocation{r}, []uuid.UUID{r.ControlID}
	payload, err := MarshalStateSnapshot(s)
	require.NoError(t, err)
	var spaced bytes.Buffer
	require.NoError(t, json.Indent(&spaced, payload, "", "  "))
	return s, append(spaced.Bytes(), '\n')
}

func TestStateRotationPreservesPayloadIdentityAndOptionalPin(t *testing.T) {
	for _, mode := range []string{"changed pin absent", "changed allocator absent", "changed allocator present", "in place"} {
		t.Run(mode, func(t *testing.T) {
			source, old, _ := stateStoreFixture(t)
			next := newStateRotationKey(t, source)
			target := filepath.Join(filepath.Dir(source), "renamed.enc")
			pin := source + ".radius-correlation"
			if mode == "changed pin absent" {
				pin = ""
			}
			if mode == "changed allocator present" {
				require.NoError(t, os.WriteFile(pin, []byte("unchanged allocator"), 0600))
			}
			inPlace := mode == "in place"
			if inPlace {
				target = source
			}
			state, payload := richStateRotationPayload(t, pin)
			writeStateRotationSource(t, source, old, state.Incarnation, payload)
			original, err := os.ReadFile(source)
			require.NoError(t, err)
			options := StateRotationOptions{InPlace: inPlace, MaxWorkingBytes: 128 << 20}
			result, err := RotateEncryptedStateStore(source, target, old, next, options)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, result.Outcome)
			require.True(t, result.Complete)
			ring, err := securestore.LoadKeyring(next)
			require.NoError(t, err)
			sealed, err := os.ReadFile(target)
			require.NoError(t, err)
			got, err := ring.Open(securestore.AdministrativeState, securestore.Binding{Store: state.Incarnation, Object: stateSnapshotObject}, sealed, MaxStateSnapshotBytes)
			require.NoError(t, err)
			require.Equal(t, payload, got, "rotation must not reconcile unfinished intents or rewrite historical fields")
			if !inPlace {
				after, err := os.ReadFile(source)
				require.NoError(t, err)
				require.Equal(t, original, after)
			}
			if mode == "changed allocator present" {
				allocator, err := os.ReadFile(pin)
				require.NoError(t, err)
				require.Equal(t, "unchanged allocator", string(allocator))
			} else if pin != "" {
				_, err := os.Stat(pin)
				require.ErrorIs(t, err, os.ErrNotExist, "rotation never opens or creates the allocator")
			}
			_, err = os.Stat(target + ".radius-correlation")
			require.ErrorIs(t, err, os.ErrNotExist, "renaming never derives a new pin")
			options.Resume = true
			result, err = RotateEncryptedStateStore(source, target, old, next, options)
			require.NoError(t, err)
			require.True(t, result.Complete)
		})
	}
}

func TestStateRotationRejectsInvalidPayloadIdentityAndPinAlias(t *testing.T) {
	for _, mode := range []string{"inner identity", "unknown field", "trailing document", "absent output aliases pin", "source aliases pin", "key aliases pin"} {
		t.Run(mode, func(t *testing.T) {
			source, old, _ := stateStoreFixture(t)
			target := filepath.Join(filepath.Dir(source), "new.enc")
			next := newStateRotationKey(t, source)
			pin := ""
			switch mode {
			case "absent output aliases pin":
				pin = target
			case "source aliases pin":
				pin = source
			case "key aliases pin":
				pin = next.Active.File
			}
			state, payload := richStateRotationPayload(t, pin)
			store := [16]byte(state.Incarnation)
			switch mode {
			case "inner identity":
				store = [16]byte(uuid.New())
			case "unknown field":
				payload = bytes.Replace(payload, []byte(`"version": 2`), []byte(`"version": 2, "PRIVATE": true`), 1)
			case "trailing document":
				payload = append(payload, []byte(`{}`)...)
			}
			writeStateRotationSource(t, source, old, store, payload)
			original, err := os.ReadFile(source)
			require.NoError(t, err)
			result, err := RotateEncryptedStateStore(source, target, old, next, StateRotationOptions{MaxWorkingBytes: 128 << 20})
			require.Error(t, err)
			require.NotContains(t, err.Error(), "PRIVATE")
			require.Equal(t, securestore.NotCommitted, result.Outcome)
			require.Equal(t, result.Outcome, securestore.OutcomeOf(err))
			_, err = os.Stat(target)
			require.ErrorIs(t, err, os.ErrNotExist)
			after, err := os.ReadFile(source)
			require.NoError(t, err)
			require.Equal(t, original, after)
		})
	}
}

func TestStateRotationOwnerSharedBudgetAndPinResult(t *testing.T) {
	state, payload := richStateRotationPayload(t, "/tmp/absent-allocator")
	before := bytes.Clone(payload)
	owner := stateRotationOwner()
	result, err := owner.Validate(payload, state.Incarnation, 1<<20)
	require.NoError(t, err)
	require.Equal(t, []string{state.RADIUSCorrelationStateFile}, result.ProtectedPaths)
	require.Equal(t, before, payload)
	_, err = owner.Validate(payload, state.Incarnation, 64<<10)
	require.ErrorContains(t, err, "decode memory")
	_, err = owner.Validate(payload, [16]byte(uuid.New()), 1<<20)
	require.ErrorIs(t, err, securestore.ErrBinding)
}
