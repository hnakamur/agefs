package agefs

import (
	"context"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fs"
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

	lf := NewFile(f, n)
	return lf, 0, 0
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
