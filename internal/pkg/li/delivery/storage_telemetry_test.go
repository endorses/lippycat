//go:build li

package delivery

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestJournalStorageTelemetrySeparatesPersistenceAndClose(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain} {
		t.Run(securestore.OutcomeName(outcome), func(t *testing.T) {
			j, err := OpenJournal(journalTestConfig(t))
			require.NoError(t, err)
			entered, release := make(chan struct{}), make(chan struct{})
			j.writeFile = func(string, []byte) error {
				close(entered)
				<-release
				return journalStorageError(outcome, errors.New("secret-payload/secret-path"))
			}
			done := make(chan error, 1)
			_, err = j.Admit(JournalRecord{Data: []byte("private-target")}, func(_ uint64, err error) { done <- err })
			require.NoError(t, err)
			<-entered
			read := make(chan securestore.StorageStatus, 1)
			go func() { read <- j.StorageStatus() }()
			select {
			case s := <-read:
				require.Equal(t, "encrypted", s.Mode)
				require.Empty(t, s.LastOutcome)
				require.NotNil(t, s.Usage)
			case <-time.After(time.Second):
				close(release)
				t.Fatal("journal status waited for fsync")
			}
			closed := make(chan error, 1)
			go func() { closed <- j.Close() }()
			require.Eventually(t, func() bool { return j.StorageStatus().State == "closing" }, time.Second, time.Millisecond)
			close(release)
			require.Error(t, <-done)
			require.Error(t, <-closed)
			s := j.StorageStatus()
			require.Equal(t, securestore.OutcomeName(outcome), s.LastOutcome)
			require.True(t, s.AdmissionBlocked)
			require.Equal(t, "closed", s.State)
			if outcome == securestore.Uncertain {
				require.Equal(t, uint64(1), s.Uncertain)
			} else {
				require.Equal(t, uint64(1), s.DefiniteFailures)
			}
			encoded, err := json.Marshal(s)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), "secret")
			require.NotContains(t, string(encoded), "private-target")
		})
	}
}
