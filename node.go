package agefs

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type ageFSNode struct {
	fs.LoopbackNode
}

var _ = (fs.NodeStatfser)((*ageFSNode)(nil))
var _ = (fs.NodeGetattrer)((*ageFSNode)(nil))
var _ = (fs.NodeGetxattrer)((*ageFSNode)(nil))
var _ = (fs.NodeSetxattrer)((*ageFSNode)(nil))
var _ = (fs.NodeRemovexattrer)((*ageFSNode)(nil))
var _ = (fs.NodeListxattrer)((*ageFSNode)(nil))
var _ = (fs.NodeReadlinker)((*ageFSNode)(nil))
var _ = (fs.NodeOpener)((*ageFSNode)(nil))
var _ = (fs.NodeCopyFileRanger)((*ageFSNode)(nil))
var _ = (fs.NodeLookuper)((*ageFSNode)(nil))
var _ = (fs.NodeOpendirer)((*ageFSNode)(nil))
var _ = (fs.NodeReaddirer)((*ageFSNode)(nil))
var _ = (fs.NodeMkdirer)((*ageFSNode)(nil))
var _ = (fs.NodeMknoder)((*ageFSNode)(nil))
var _ = (fs.NodeLinker)((*ageFSNode)(nil))
var _ = (fs.NodeSymlinker)((*ageFSNode)(nil))
var _ = (fs.NodeUnlinker)((*ageFSNode)(nil))
var _ = (fs.NodeRmdirer)((*ageFSNode)(nil))
var _ = (fs.NodeRenamer)((*ageFSNode)(nil))

func (n *ageFSNode) root() *ageFSRoot {
	return (*ageFSRoot)(unsafe.Pointer(n.RootData))
}

func (n *ageFSNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	flags = flags &^ syscall.O_APPEND
	p := n.path()
	f, err := syscall.Open(p, int(flags), 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}

	relPath := n.relPath()
	lf := newFile(f, relPath, n)
	return lf, 0, 0
}

var _ = (fs.NodeCreater)((*ageFSNode)(nil))

func (n *ageFSNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	p := filepath.Join(n.path(), name)
	flags = flags &^ syscall.O_APPEND
	fd, err := syscall.Open(p, int(flags)|os.O_CREATE, mode)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	n.preserveOwner(ctx, p)
	st := syscall.Stat_t{}
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, nil, 0, fs.ToErrno(err)
	}

	node := n.root().newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.root().idFromStat(&st))
	relPath := filepath.Join(n.relPath(), name)
	lf := newFile(fd, relPath, n)

	out.FromStat(&st)
	return ch, lf, 0, 0
}

// path returns the full path to the file in the underlying file
// system.
func (n *ageFSNode) path() string {
	path := n.Path(n.Root())
	return filepath.Join(n.RootData.Path, path)
}

func (n *ageFSNode) relPath() string {
	return n.Path(n.Root())
}

func (n *ageFSNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	p := filepath.Join(n.path(), name)
	log.Printf("ageFSNode.Lookup path=%s", p)

	st := syscall.Stat_t{}
	err := syscall.Lstat(p, &st)
	if err != nil {
		return nil, fs.ToErrno(err)
	}

	out.Attr.FromStat(&st)

	log.Printf("ageFSNode.Lookup calling fixAttrSize, path=%s", n.path())
	if err := fixAttrSize(p, &out.Attr.Size); err != nil {
		return nil, fs.ToErrno(err)
	}

	node := n.root().newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.root().idFromStat(&st))
	return ch, 0
}

// preserveOwner sets uid and gid of `path` according to the caller information
// in `ctx`.
func (n *ageFSNode) preserveOwner(ctx context.Context, path string) error {
	if os.Getuid() != 0 {
		return nil
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return nil
	}
	return syscall.Lchown(path, int(caller.Uid), int(caller.Gid))
}

func (n *ageFSNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	log.Printf("ageFSNode.Readdir, path=%s", n.path())
	return fs.NewLoopbackDirStream(n.path())
}

func (n *ageFSNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	log.Printf("ageFSNode.Getattr path=%s, f=%v (%T)", n.path(), f, f)
	if f != nil {
		return f.(fs.FileGetattrer).Getattr(ctx, out)
	}

	p := n.path()

	var err error
	st := syscall.Stat_t{}
	if &n.Inode == n.Root() {
		err = syscall.Stat(p, &st)
	} else {
		err = syscall.Lstat(p, &st)
	}

	if err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)

	// log.Printf("ageFSNode.Getattr calling fixAttrSize, path=%s", n.path())
	// if err := fixAttrSize(p, out); err != nil {
	// 	return fs.ToErrno(err)
	// }

	return fs.OK
}

func (n *ageFSNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	p := n.path()
	log.Printf("ageFSFile.Setattr start, path=%v, in=%+v, f=%v", p, in, f)
	if in != nil {
		log.Printf("ageFSFile.Setattr start, path=%v, in.Size=%+v", p, in.Size)
	}
	fsa, ok := f.(fs.FileSetattrer)
	if ok && fsa != nil {
		fsa.Setattr(ctx, in, out)
	} else {
		if m, ok := in.GetMode(); ok {
			if err := syscall.Chmod(p, m); err != nil {
				return fs.ToErrno(err)
			}
		}

		uid, uok := in.GetUID()
		gid, gok := in.GetGID()
		if uok || gok {
			suid := -1
			sgid := -1
			if uok {
				suid = int(uid)
			}
			if gok {
				sgid = int(gid)
			}
			if err := syscall.Chown(p, suid, sgid); err != nil {
				return fs.ToErrno(err)
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
			var ts [2]syscall.Timespec
			ts[0] = fuse.UtimeToTimespec(ap)
			ts[1] = fuse.UtimeToTimespec(mp)

			if err := syscall.UtimesNano(p, ts[:]); err != nil {
				return fs.ToErrno(err)
			}
		}

		if sz, ok := in.GetSize(); ok {
			if err := syscall.Truncate(p, int64(sz)); err != nil {
				return fs.ToErrno(err)
			}
		}
	}

	fga, ok := f.(fs.FileGetattrer)
	if ok && fga != nil {
		fga.Getattr(ctx, out)
	} else {
		st := syscall.Stat_t{}
		err := syscall.Lstat(p, &st)
		if err != nil {
			return fs.ToErrno(err)
		}
		out.FromStat(&st)
	}
	return fs.OK
}
