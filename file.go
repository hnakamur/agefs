package agefs

import (
	"bytes"
	"context"
	"io"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hnakamur/ageutil"
)

type ageFSFile struct {
	mu            sync.Mutex
	fd            int
	node          *Node
	shouldEncrypt bool
	buf           *bytes.Buffer
}

var _ = (fs.FileHandle)((*ageFSFile)(nil))

var _ = (fs.FileReleaser)((*ageFSFile)(nil))
var _ = (fs.FileGetattrer)((*ageFSFile)(nil))
var _ = (fs.FileReader)((*ageFSFile)(nil))

// var _ = (fs.FileWriter)((*ageFSFile)(nil))
// var _ = (fs.FileGetlker)((*ageFSFile)(nil))
// var _ = (fs.FileSetlker)((*ageFSFile)(nil))
// var _ = (fs.FileSetlkwer)((*ageFSFile)(nil))
// var _ = (fs.FileLseeker)((*ageFSFile)(nil))
var _ = (fs.FileFlusher)((*ageFSFile)(nil))

// var _ = (fs.FileFsyncer)((*ageFSFile)(nil))
// var _ = (fs.FileSetattrer)((*ageFSFile)(nil))
// var _ = (fs.FileAllocater)((*ageFSFile)(nil))

func NewFile(fd int, node *Node) *ageFSFile {
	shouldEncrypt := node.AgeFSRoot().shouldEncrypt(node.relPath())
	return &ageFSFile{
		fd:            fd,
		node:          node,
		shouldEncrypt: shouldEncrypt,
	}
}

func (f *ageFSFile) Read(ctx context.Context, buf []byte, off int64) (res fuse.ReadResult, errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.shouldEncrypt {
		r := fuse.ReadResultFd(uintptr(f.fd), off, len(buf))
		return r, fs.OK
	}

	if f.buf == nil {
		st := syscall.Stat_t{}
		if err := syscall.Fstat(f.fd, &st); err != nil {
			return nil, fs.ToErrno(err)
		}

		encryptedBuf := make([]byte, st.Size)
		n, err := syscall.Pread(int(f.fd), encryptedBuf, 0)
		if err == io.EOF {
			err = nil
		}
		if n < 0 {
			n = 0
		}
		if int64(n) < st.Size {
			return nil, fs.ToErrno(io.EOF)
		}

		var decrypted bytes.Buffer
		if err := ageutil.Decrypt(f.node.AgeFSRoot().identities, bytes.NewReader(encryptedBuf), &decrypted); err != nil {
			return nil, fs.ToErrno(err)
		}
		f.buf = &decrypted
	}

	fBytes := f.buf.Bytes()
	end := int(off) + len(buf)
	if end > len(fBytes) {
		end = len(fBytes)
	}
	data := fBytes[off:end]
	return fuse.ReadResultData(data), fs.OK
}

func (f *ageFSFile) Release(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fd != -1 {
		err := syscall.Close(f.fd)
		f.fd = -1
		return fs.ToErrno(err)
	}
	return syscall.EBADF
}

func (f *ageFSFile) Flush(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Since Flush() may be called for each dup'd fd, we don't
	// want to really close the file, we just want to flush. This
	// is achieved by closing a dup'd fd.
	newFd, err := syscall.Dup(f.fd)

	if err != nil {
		return fs.ToErrno(err)
	}
	err = syscall.Close(newFd)
	return fs.ToErrno(err)
}

func (f *ageFSFile) Getattr(ctx context.Context, a *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := syscall.Stat_t{}
	err := syscall.Fstat(f.fd, &st)
	if err != nil {
		return fs.ToErrno(err)
	}
	a.FromStat(&st)

	return fs.OK
}
