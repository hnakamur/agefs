package agefs

import (
	"syscall"

	"filippo.io/age"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hnakamur/agefs/internal/ageutil"
)

type ShouldEncryptFunc func(path string) bool

type ageFSRoot struct {
	fs.LoopbackRoot
	identities    []age.Identity
	recipients    []age.Recipient
	shouldEncrypt ShouldEncryptFunc
}

func NewRoot(rootPath string, identities []age.Identity, shouldEncrypt ShouldEncryptFunc) (fs.InodeEmbedder, error) {
	recipients, err := ageutil.IdentitiesToRecipients(identities)
	if err != nil {
		return nil, err
	}

	var st syscall.Stat_t
	err = syscall.Stat(rootPath, &st)
	if err != nil {
		return nil, err
	}

	root := &ageFSRoot{
		LoopbackRoot: fs.LoopbackRoot{
			Path: rootPath,
			Dev:  uint64(st.Dev),
			NewNode: func(rootData *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
				n := &ageFSNode{
					LoopbackNode: fs.LoopbackNode{
						RootData: rootData,
					},
				}
				return n
			},
		},
		identities:    identities,
		recipients:    recipients,
		shouldEncrypt: shouldEncrypt,
	}

	return root.newNode(nil, "", &st), nil
}

func (r *ageFSRoot) newNode(parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
	if r.NewNode != nil {
		return r.LoopbackRoot.NewNode(&r.LoopbackRoot, parent, name, st)
	}
	return &ageFSNode{
		LoopbackNode: fs.LoopbackNode{
			RootData: &r.LoopbackRoot,
		},
	}
}

func (r *ageFSRoot) idFromStat(st *syscall.Stat_t) fs.StableAttr {
	// We compose an inode number by the underlying inode, and
	// mixing in the device number. In traditional filesystems,
	// the inode numbers are small. The device numbers are also
	// small (typically 16 bit). Finally, we mask out the root
	// device number of the root, so a loopback FS that does not
	// encompass multiple mounts will reflect the inode numbers of
	// the underlying filesystem
	swapped := (uint64(st.Dev) << 32) | (uint64(st.Dev) >> 32)
	swappedRootDev := (r.Dev << 32) | (r.Dev >> 32)
	return fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		// This should work well for traditional backing FSes,
		// not so much for other go-fuse FS-es
		Ino: (swapped ^ swappedRootDev) ^ st.Ino,
	}
}
