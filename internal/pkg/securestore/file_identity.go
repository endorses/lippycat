package securestore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// FileIdentity is descriptor-derived filesystem identity, not a key fingerprint.
type FileIdentity struct{ Device, Inode uint64 }

func ReadFileWithIdentity(path string, maxBytes int64) (_ []byte, identity FileIdentity, result error) {
	parent, name := ".", path
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		parent, name = path[:slash], path[slash+1:]
		if parent == "" {
			parent = "/"
		}
	}
	if err := checkName(name); err != nil {
		return nil, identity, err
	}
	dir, err := openDirectory(parent, false)
	if err != nil {
		return nil, identity, err
	}
	defer func() { result = errors.Join(result, contextual("close private file directory", dir.Close())) }()
	file, err := openPrivate(int(dir.Fd()), name)
	if err != nil {
		return nil, identity, err
	}
	defer func() { result = errors.Join(result, contextual("close identified private file", file.Close())) }()
	data, err := readOpenedPrivate(file, maxBytes)
	if err != nil {
		return nil, identity, err
	}
	stat, err := validatePrivate(int(file.Fd()))
	if err != nil {
		return nil, identity, err
	}
	return data, FileIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}

func readOpenedPrivate(file *os.File, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, errors.New("securestore: negative read limit")
	}
	st, err := validatePrivate(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	if st.Size < 0 || st.Size > maxBytes || uint64(st.Size) > uint64(int(^uint(0)>>1)) {
		return nil, errors.New("securestore: private file exceeds read limit")
	}
	data := make([]byte, int(st.Size))
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("securestore: read private file: %w", err)
	}
	var extra [1]byte
	n, err := file.Read(extra[:])
	if n != 0 || err != io.EOF {
		return nil, errors.New("securestore: private file changed during read")
	}
	final, err := validatePrivate(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	if final.Size != st.Size {
		return nil, errors.New("securestore: private file changed during read")
	}
	return data, nil
}

func (d *Dir) FileIdentity(name string) (_ FileIdentity, result error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := checkName(name); err != nil {
		return FileIdentity{}, err
	}
	if d.file == nil {
		return FileIdentity{}, os.ErrClosed
	}
	file, err := openPrivate(int(d.file.Fd()), name)
	if err != nil {
		return FileIdentity{}, err
	}
	defer func() { result = errors.Join(result, contextual("close identity inspection", file.Close())) }()
	stat, err := validatePrivate(int(file.Fd()))
	if err != nil {
		return FileIdentity{}, err
	}
	return FileIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}
