package agefs

import (
	"context"
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

	st := syscall.Stat_t{}
	err := syscall.Lstat(p, &st)
	if err != nil {
		return nil, fs.ToErrno(err)
	}

	out.Attr.FromStat(&st)

	// override file size with unencrpyted size
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
