package agefs

import (
	"syscall"

	"filippo.io/age"
	"github.com/hanwen/go-fuse/v2/fs"
)

type ShouldEncryptFunc func(path string) bool

type Root struct {
	fs.LoopbackRoot
	identities    []age.Identity
	shouldEncrypt ShouldEncryptFunc
}

func NewRoot(rootPath string, identities []age.Identity, shouldEncrypt ShouldEncryptFunc) (fs.InodeEmbedder, error) {
	var st syscall.Stat_t
	err := syscall.Stat(rootPath, &st)
	if err != nil {
		return nil, err
	}

	root := &Root{
		LoopbackRoot: fs.LoopbackRoot{
			Path: rootPath,
			Dev:  uint64(st.Dev),
			NewNode: func(rootData *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
				n := &Node{
					LoopbackNode: fs.LoopbackNode{
						RootData: rootData,
					},
				}
				return n
			},
		},
		identities:    identities,
		shouldEncrypt: shouldEncrypt,
	}

	return root.NewNode(&root.LoopbackRoot, nil, "", &st), nil
}
