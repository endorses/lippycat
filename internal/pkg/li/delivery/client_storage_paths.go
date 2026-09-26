//go:build li

package delivery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// Validate all configured ownership boundaries before either journal can recover
// temporaries or initialize storage. OpenDir examines the uncleaned path first.
func (c *Client) validateStoragePaths() (result error) {
	paths := []string{c.config.X2SpoolDir, c.config.X3SpoolDir}
	var dirs []*securestore.Dir
	defer func() {
		for _, d := range dirs {
			result = errors.Join(result, d.Close())
		}
	}()
	var absolute []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		d, err := securestore.OpenDir(p)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if d != nil {
			for _, other := range dirs {
				same, e := d.SameDirectory(other)
				if e != nil || same {
					return errors.Join(fmt.Errorf("delivery journals require independent directories"), e, d.Close())
				}
			}
			dirs = append(dirs, d)
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		for _, other := range absolute {
			if storagePathContains(abs, other) || storagePathContains(other, abs) {
				return fmt.Errorf("delivery journal directories overlap")
			}
		}
		absolute = append(absolute, abs)
	}
	protected := append([]string(nil), c.config.ProtectedStoragePaths...)
	protected = append(protected, c.config.X2SpoolKeyFile, c.config.X3SpoolKeyFile)
	for _, ref := range append(append([]securestore.KeyRef(nil), c.config.X2SpoolReadKeys...), c.config.X3SpoolReadKeys...) {
		protected = append(protected, ref.File)
	}
	for _, p := range protected {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		for _, dir := range absolute {
			if storagePathContains(dir, abs) || storagePathContains(abs, dir) {
				return fmt.Errorf("journal aliases protected storage path")
			}
		}
		parent := filepath.Dir(p)
		for _, journal := range dirs {
			same, e := journal.SameDirectoryPath(parent)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil || same {
				return errors.Join(fmt.Errorf("journal owns protected storage parent"), e)
			}
		}
	}
	return nil
}
func storagePathContains(parent, path string) bool {
	return parent == path || strings.HasPrefix(path, parent+string(filepath.Separator))
}
