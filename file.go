// Copyright 2019 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agefs

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"filippo.io/age"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hnakamur/agefs/internal/ageutil"
	"golang.org/x/sys/unix"
)

type ageFSFile struct {
	mu            sync.Mutex
	fd            int
	relPath       string
	node          *ageFSNode
	shouldEncrypt bool
	buf           []byte
	dirty         bool
}

var _ = (fs.FileHandle)((*ageFSFile)(nil))

var _ = (fs.FileReleaser)((*ageFSFile)(nil))
var _ = (fs.FileGetattrer)((*ageFSFile)(nil))
var _ = (fs.FileReader)((*ageFSFile)(nil))
var _ = (fs.FileWriter)((*ageFSFile)(nil))
var _ = (fs.FileGetlker)((*ageFSFile)(nil))
var _ = (fs.FileSetlker)((*ageFSFile)(nil))
var _ = (fs.FileSetlkwer)((*ageFSFile)(nil))
var _ = (fs.FileLseeker)((*ageFSFile)(nil))
var _ = (fs.FileFlusher)((*ageFSFile)(nil))
var _ = (fs.FileFsyncer)((*ageFSFile)(nil))
var _ = (fs.FileSetattrer)((*ageFSFile)(nil))
var _ = (fs.FileAllocater)((*ageFSFile)(nil))

const xattrNameDecryptedSize = "user.agefs_decrypted_size"

func newFile(fd int, relPath string, node *ageFSNode) *ageFSFile {
	shouldEncrypt := node.root().shouldEncrypt(relPath)
	return &ageFSFile{
		fd:            fd,
		relPath:       relPath,
		node:          node,
		shouldEncrypt: shouldEncrypt,
	}
}

func (f *ageFSFile) path() string {
	return filepath.Join(f.node.RootData.Path, f.relPath)
}

func (f *ageFSFile) Read(ctx context.Context, buf []byte, off int64) (res fuse.ReadResult, errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.shouldEncrypt {
		r := fuse.ReadResultFd(uintptr(f.fd), off, len(buf))
		return r, fs.OK
	}

	if err := f.readAndDecryptFileIfNeeded(f.fd); err != nil {
		return nil, fs.ToErrno(err)
	}
	end := int(off) + len(buf)
	if end > len(f.buf) {
		end = len(f.buf)
	}
	data := f.buf[off:end]
	return fuse.ReadResultData(data), fs.OK
}

func (f *ageFSFile) readAndDecryptFileIfNeeded(fd int) error {
	if f.buf != nil {
		return nil
	}

	file := os.NewFile(uintptr(fd), f.path())

	br := bufio.NewReader(file)
	ew, err := ageutil.NewDecryptingReader(f.node.root().identities, br)
	if err != nil {
		return err
	}
	var decrypted bytes.Buffer
	if _, err := io.Copy(&decrypted, ew); err != nil {
		return err
	}
	f.buf = decrypted.Bytes()
	return nil
}

func (f *ageFSFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.shouldEncrypt {
		n, err := syscall.Pwrite(f.fd, data, off)
		return uint32(n), fs.ToErrno(err)
	}

	end := int(off) + len(data)
	f.dirty = true
	if f.buf == nil {
		f.buf = make([]byte, end)
	} else if len(f.buf) < end {
		newBuf := make([]byte, end)
		copy(newBuf, f.buf)
		f.buf = newBuf
	}
	copy(f.buf[off:end], data)
	return uint32(len(data)), fs.OK
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

	if err := f.saveEncrypted(ctx); err != nil {
		return fs.ToErrno(err)
	}
	f.buf = nil

	err = syscall.Close(newFd)
	return fs.ToErrno(err)
}

func (f *ageFSFile) Fsync(ctx context.Context, flags uint32) (errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.saveEncrypted(ctx); err != nil {
		return fs.ToErrno(err)
	}

	r := fs.ToErrno(syscall.Fsync(f.fd))
	return r
}

func (f *ageFSFile) saveEncrypted(ctx context.Context) (err error) {
	if !f.dirty {
		return nil
	}

	path := f.path()
	file := os.NewFile(uintptr(f.fd), path)

	w, err := age.Encrypt(file, f.node.root().recipients...)
	if err != nil {
		return err
	}
	if _, err := w.Write(f.buf); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	// Set unencrypted file size as a xattr attribute.
	value := strconv.FormatUint(uint64(len(f.buf)), 10)
	if err := syscall.Setxattr(path, xattrNameDecryptedSize, []byte(value), 0); err != nil {
		return err
	}

	f.dirty = false
	return nil
}

const (
	_OFD_GETLK  = 36
	_OFD_SETLK  = 37
	_OFD_SETLKW = 38
)

func (f *ageFSFile) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) (errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	flk := syscall.Flock_t{}
	lk.ToFlockT(&flk)
	errno = fs.ToErrno(syscall.FcntlFlock(uintptr(f.fd), _OFD_GETLK, &flk))
	out.FromFlockT(&flk)
	return
}

func (f *ageFSFile) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) (errno syscall.Errno) {
	return f.setLock(ctx, owner, lk, flags, false)
}

func (f *ageFSFile) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) (errno syscall.Errno) {
	return f.setLock(ctx, owner, lk, flags, true)
}

func (f *ageFSFile) setLock(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, blocking bool) (errno syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if (flags & fuse.FUSE_LK_FLOCK) != 0 {
		var op int
		switch lk.Typ {
		case syscall.F_RDLCK:
			op = syscall.LOCK_SH
		case syscall.F_WRLCK:
			op = syscall.LOCK_EX
		case syscall.F_UNLCK:
			op = syscall.LOCK_UN
		default:
			return syscall.EINVAL
		}
		if !blocking {
			op |= syscall.LOCK_NB
		}
		return fs.ToErrno(syscall.Flock(f.fd, op))
	} else {
		flk := syscall.Flock_t{}
		lk.ToFlockT(&flk)
		var op int
		if blocking {
			op = _OFD_SETLKW
		} else {
			op = _OFD_SETLK
		}
		return fs.ToErrno(syscall.FcntlFlock(uintptr(f.fd), op, &flk))
	}
}

func (f *ageFSFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := f.setAttr(ctx, in); errno != 0 {
		return errno
	}

	return f.Getattr(ctx, out)
}

func (f *ageFSFile) setAttr(ctx context.Context, in *fuse.SetAttrIn) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errno syscall.Errno
	if mode, ok := in.GetMode(); ok {
		errno = fs.ToErrno(syscall.Fchmod(f.fd, mode))
		if errno != 0 {
			return errno
		}
	}

	uid32, uOk := in.GetUID()
	gid32, gOk := in.GetGID()
	if uOk || gOk {
		uid := -1
		gid := -1

		if uOk {
			uid = int(uid32)
		}
		if gOk {
			gid = int(gid32)
		}
		errno = fs.ToErrno(syscall.Fchown(f.fd, uid, gid))
		if errno != 0 {
			return errno
		}
	}

	mtime, mok := in.GetMTime()
	atime, aok := in.GetATime()

	if mok || aok {
		ap := &atime
		mp := &mtime
		if !aok {
			ap = nil
		}
		if !mok {
			mp = nil
		}
		errno = f.utimens(ap, mp)
		if errno != 0 {
			return errno
		}
	}

	if sz, ok := in.GetSize(); ok {
		if f.shouldEncrypt {
			if sz > 0 && f.buf == nil {
				fd, err := syscall.Open(f.path(), os.O_RDONLY, 0)
				if err != nil {
					return fs.ToErrno(err)
				}
				if err := f.readAndDecryptFileIfNeeded(fd); err != nil {
					syscall.Close(fd)
					return fs.ToErrno(err)
				}
				if err := syscall.Close(fd); err != nil {
					return fs.ToErrno(err)
				}
			}

			errno = fs.ToErrno(syscall.Ftruncate(f.fd, 0))
			if errno != 0 {
				return errno
			}

			newBuf := make([]byte, sz)
			copy(newBuf, f.buf)
			f.buf = newBuf
			f.dirty = true
			if err := f.saveEncrypted(ctx); err != nil {
				return fs.ToErrno(err)
			}
		} else {
			// TODO: truncate f.buf and write it to file instead of call fruncate if encrypted and sz < len(f.buf)
			// TODO: what to do if sz > len(f.buf)? we cannot make a hole for encrypted file
			errno = fs.ToErrno(syscall.Ftruncate(f.fd, int64(sz)))
			if errno != 0 {
				return errno
			}
		}
	}
	return fs.OK
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

func (f *ageFSFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := unix.Seek(f.fd, int64(off), int(whence))
	return uint64(n), fs.ToErrno(err)
}
