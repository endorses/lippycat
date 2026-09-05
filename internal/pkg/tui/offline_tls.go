//go:build tui || all

package tui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
)

// Offline keys are loaded once with bounded line memory. No file watcher can
// change the meaning of a completed session after atomic publication.
func newOfflineTLSDecryptor(ctx context.Context, path string) (result *TLSDecryptor, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("offline TLS key log must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("offline TLS key log must be a regular file")
	}
	d, err := NewTLSDecryptor("")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			d.Stop()
		}
	}()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	parser := keylog.NewParser()
	for scanner.Scan() {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var entry *keylog.KeyEntry
		entry, err = parser.ParseLine(scanner.Text())
		if err != nil {
			return nil, err
		}
		if entry != nil {
			d.keyStore.Add(entry)
		}
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	return d, nil
}
