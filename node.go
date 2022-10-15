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

type Node struct {
	fs.LoopbackNode
}

var _ = (fs.NodeStatfser)((*Node)(nil))
var _ = (fs.NodeStatfser)((*Node)(nil))
var _ = (fs.NodeGetattrer)((*Node)(nil))
var _ = (fs.NodeGetxattrer)((*Node)(nil))
var _ = (fs.NodeSetxattrer)((*Node)(nil))
var _ = (fs.NodeRemovexattrer)((*Node)(nil))
var _ = (fs.NodeListxattrer)((*Node)(nil))
var _ = (fs.NodeReadlinker)((*Node)(nil))
var _ = (fs.NodeOpener)((*Node)(nil))
var _ = (fs.NodeCopyFileRanger)((*Node)(nil))
var _ = (fs.NodeLookuper)((*Node)(nil))
var _ = (fs.NodeOpendirer)((*Node)(nil))
var _ = (fs.NodeReaddirer)((*Node)(nil))
var _ = (fs.NodeMkdirer)((*Node)(nil))
var _ = (fs.NodeMknoder)((*Node)(nil))
var _ = (fs.NodeLinker)((*Node)(nil))
var _ = (fs.NodeSymlinker)((*Node)(nil))
var _ = (fs.NodeUnlinker)((*Node)(nil))
var _ = (fs.NodeRmdirer)((*Node)(nil))
var _ = (fs.NodeRenamer)((*Node)(nil))

func (n *Node) AgeFSRoot() *Root {
	return (*Root)(unsafe.Pointer(n.RootData))
}

func (n *Node) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	flags = flags &^ syscall.O_APPEND
	p := n.path()
	f, err := syscall.Open(p, int(flags), 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}

	relPath := n.relPath()
	log.Printf("agefs.Node.Open calling NewFile, relPath=%q", relPath)
	lf := NewFile(f, relPath, n)
	return lf, 0, 0
}

var _ = (fs.NodeCreater)((*Node)(nil))

func (n *Node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
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

	node := n.AgeFSRoot().newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.AgeFSRoot().idFromStat(&st))
	relPath := filepath.Join(n.relPath(), name)
	log.Printf("agefs.Node.Create calling NewFile, relPath=%q, nodeId=%d", relPath, n.LoopbackNode.StableAttr().Ino)
	lf := NewFile(fd, relPath, n)

	out.FromStat(&st)
	return ch, lf, 0, 0
}

// path returns the full path to the file in the underlying file
// system.
func (n *Node) path() string {
	path := n.Path(n.Root())
	return filepath.Join(n.RootData.Path, path)
}

func (n *Node) relPath() string {
	return n.Path(n.Root())
}

// preserveOwner sets uid and gid of `path` according to the caller information
// in `ctx`.
func (n *Node) preserveOwner(ctx context.Context, path string) error {
	if os.Getuid() != 0 {
		return nil
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return nil
	}
	return syscall.Lchown(path, int(caller.Uid), int(caller.Gid))
}
