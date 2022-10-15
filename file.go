// Copyright 2019 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agefs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"filippo.io/age"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hnakamur/ageutil"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
)

type ageFSFile struct {
	mu            sync.Mutex
	fd            int
	relPath       string
	node          *Node
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

func NewFile(fd int, relPath string, node *Node) *ageFSFile {
	shouldEncrypt := node.AgeFSRoot().shouldEncrypt(relPath)
	log.Printf("NewFile, path=%s, relPath=%s, shouldEncrypt=%v", node.path(), node.relPath(), shouldEncrypt)
	return &ageFSFile{
		fd:            fd,
		relPath:       relPath,
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
		f.buf = decrypted.Bytes()
	}

	fBytes := f.buf
	end := int(off) + len(buf)
	if end > len(fBytes) {
		end = len(fBytes)
	}
	data := fBytes[off:end]
	return fuse.ReadResultData(data), fs.OK
}

func (f *ageFSFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	log.Printf("ageFSFile.Write start, data=%s, off=%d, relPath=%s, shouldEncrypt=%v", data, off, f.relPath, f.shouldEncrypt)
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
	log.Printf("ageFSFile.Write updated buf=%s", string(f.buf))
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

	root := f.node.AgeFSRoot()
	path := filepath.Join(root.LoopbackRoot.Path, f.relPath)
	dir := filepath.Dir(path)
	pattern := "." + filepath.Base(path) + "."
	tf, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return fmt.Errorf("create temp encrypted file, dir=%s, pattern=%s: %s", dir, pattern, err)
	}
	defer func() {
		if err != nil {
			err = multierr.Append(err, os.Remove(tf.Name()))
		}
	}()

	tfst := syscall.Stat_t{}
	if err = syscall.Fstat(int(tf.Fd()), &tfst); err != nil {
		return err
	}

	st := syscall.Stat_t{}
	if err = syscall.Lstat(path, &st); err != nil {
		return err
	}
	if err = tf.Chmod(os.FileMode(st.Mode) & os.ModePerm); err != nil {
		return err
	}
	log.Printf("tfst.Ino=%d, st.Ino=%d", tfst.Ino, st.Ino)

	w, err := age.Encrypt(tf, root.recipients...)
	if err != nil {
		return err
	}
	if _, err := w.Write(f.buf); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err = tf.Sync(); err != nil {
		return fmt.Errorf("sync temp encrypted file, path=%s: %s", tf.Name(), err)
	}
	if err = tf.Close(); err != nil {
		return fmt.Errorf("close temp encrypted file, path=%s: %s", tf.Name(), err)
	}
	if err = os.Rename(tf.Name(), path); err != nil {
		return fmt.Errorf("rename temp encrypted file, tempName=%s, path=%s: %s", tf.Name(), path, err)
	}

	st2 := syscall.Stat_t{}
	if err = syscall.Lstat(path, &st2); err != nil {
		return err
	}
	log.Printf("st.Ino=%d, st2.Ino=%d", st.Ino, st2.Ino)

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
		errno = fs.ToErrno(syscall.Ftruncate(f.fd, int64(sz)))
		if errno != 0 {
			return errno
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
