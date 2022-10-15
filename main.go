package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"filippo.io/age"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hnakamur/ageutil"
)

type ShouldEncryptFunc func(path string) bool

type AgeFSRoot struct {
	fs.LoopbackRoot
	identities    []age.Identity
	shouldEncrypt ShouldEncryptFunc
}

type AgeFSNode struct {
	fs.LoopbackNode
}

var _ = (fs.NodeStatfser)((*AgeFSNode)(nil))
var _ = (fs.NodeStatfser)((*AgeFSNode)(nil))
var _ = (fs.NodeGetattrer)((*AgeFSNode)(nil))
var _ = (fs.NodeGetxattrer)((*AgeFSNode)(nil))
var _ = (fs.NodeSetxattrer)((*AgeFSNode)(nil))
var _ = (fs.NodeRemovexattrer)((*AgeFSNode)(nil))
var _ = (fs.NodeListxattrer)((*AgeFSNode)(nil))
var _ = (fs.NodeReadlinker)((*AgeFSNode)(nil))
var _ = (fs.NodeOpener)((*AgeFSNode)(nil))
var _ = (fs.NodeCopyFileRanger)((*AgeFSNode)(nil))
var _ = (fs.NodeLookuper)((*AgeFSNode)(nil))
var _ = (fs.NodeOpendirer)((*AgeFSNode)(nil))
var _ = (fs.NodeReaddirer)((*AgeFSNode)(nil))
var _ = (fs.NodeMkdirer)((*AgeFSNode)(nil))
var _ = (fs.NodeMknoder)((*AgeFSNode)(nil))
var _ = (fs.NodeLinker)((*AgeFSNode)(nil))
var _ = (fs.NodeSymlinker)((*AgeFSNode)(nil))
var _ = (fs.NodeUnlinker)((*AgeFSNode)(nil))
var _ = (fs.NodeRmdirer)((*AgeFSNode)(nil))
var _ = (fs.NodeRenamer)((*AgeFSNode)(nil))

type ageFSFile struct {
	mu            sync.Mutex
	fd            int
	node          *AgeFSNode
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

func NewAgeFSRoot(rootPath string, identities []age.Identity, shouldEncrypt ShouldEncryptFunc) (fs.InodeEmbedder, error) {
	var st syscall.Stat_t
	err := syscall.Stat(rootPath, &st)
	if err != nil {
		return nil, err
	}

	root := &AgeFSRoot{
		LoopbackRoot: fs.LoopbackRoot{
			Path: rootPath,
			Dev:  uint64(st.Dev),
			NewNode: func(rootData *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
				n := &AgeFSNode{
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

func (n *AgeFSNode) AgeFSRoot() *AgeFSRoot {
	return (*AgeFSRoot)(unsafe.Pointer(n.RootData))
}

func (n *AgeFSNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	flags = flags &^ syscall.O_APPEND
	p := n.path()
	f, err := syscall.Open(p, int(flags), 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}

	lf := NewAgeFSFile(f, n)
	return lf, 0, 0
}

// path returns the full path to the file in the underlying file
// system.
func (n *AgeFSNode) path() string {
	path := n.Path(n.Root())
	return filepath.Join(n.RootData.Path, path)
}

func (n *AgeFSNode) relPath() string {
	return n.Path(n.Root())
}

func NewAgeFSFile(fd int, node *AgeFSNode) *ageFSFile {
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

func writeMemProfile(fn string, sigs <-chan os.Signal) {
	i := 0
	for range sigs {
		fn := fmt.Sprintf("%s-%d.memprof", fn, i)
		i++

		log.Printf("Writing mem profile to %s\n", fn)
		f, err := os.Create(fn)
		if err != nil {
			log.Printf("Create: %v", err)
			continue
		}
		pprof.WriteHeapProfile(f)
		if err := f.Close(); err != nil {
			log.Printf("close %v", err)
		}
	}
}

func main() {
	log.SetFlags(log.Lmicroseconds)
	// Scans the arg list and sets up flags
	debug := flag.Bool("debug", false, "print debugging messages.")
	other := flag.Bool("allow-other", false, "mount with -o allowother.")
	quiet := flag.Bool("q", false, "quiet")
	ro := flag.Bool("ro", false, "mount read-only")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to this file")
	memprofile := flag.String("memprofile", "", "write memory profile to this file")
	privName := flag.String("priv", "", "private key filename")
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Printf("usage: %s ORIGINAL MOUNTPOINT\n", path.Base(os.Args[0]))
		fmt.Printf("\noptions:\n")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if *privName == "" {
		fmt.Printf("private key filename must be set with -priv flag.")
		os.Exit(2)
	}
	if *cpuprofile != "" {
		if !*quiet {
			fmt.Printf("Writing cpu profile to %s\n", *cpuprofile)
		}
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	if *memprofile != "" {
		if !*quiet {
			log.Printf("send SIGUSR1 to %d to dump memory profile", os.Getpid())
		}
		profSig := make(chan os.Signal, 1)
		signal.Notify(profSig, syscall.SIGUSR1)
		go writeMemProfile(*memprofile, profSig)
	}
	if *cpuprofile != "" || *memprofile != "" {
		if !*quiet {
			fmt.Printf("Note: You must unmount gracefully, otherwise the profile file(s) will stay empty!\n")
		}
	}

	readPassphrase := func() ([]byte, error) {
		pass, err := ageutil.ReadSecretFromTerminal(fmt.Sprintf("Enter passphrase for %q:", *privName))
		if err != nil {
			return nil, fmt.Errorf("could not read passphrase for %q: %v", *privName, err)
		}
		return pass, nil
	}
	identities, err := ageutil.ParseSSHPrivateKeyFile(*privName, readPassphrase)
	if err != nil {
		fmt.Printf("failed to load private key: %s", err)
		os.Exit(1)
	}

	orig := flag.Arg(0)
	shouldEncrypt := func(path string) bool {
		return strings.HasSuffix(path, ".age") || strings.HasSuffix(path, ".age.pem")
	}
	loopbackRoot, err := NewAgeFSRoot(orig, identities, shouldEncrypt)
	if err != nil {
		log.Fatalf("NewLoopbackRoot(%s): %v\n", orig, err)
	}

	sec := time.Second
	opts := &fs.Options{
		// These options are to be compatible with libfuse defaults,
		// making benchmarking easier.
		AttrTimeout:  &sec,
		EntryTimeout: &sec,
	}
	opts.Debug = *debug
	opts.AllowOther = *other
	if opts.AllowOther {
		// Make the kernel check file permissions for us
		opts.MountOptions.Options = append(opts.MountOptions.Options, "default_permissions")
	}
	if *ro {
		opts.MountOptions.Options = append(opts.MountOptions.Options, "ro")
	}
	// First column in "df -T": original dir
	opts.MountOptions.Options = append(opts.MountOptions.Options, "fsname="+orig)
	// Second column in "df -T" will be shown as "fuse." + Name
	opts.MountOptions.Name = "loopback"
	// Leave file permissions on "000" files as-is
	opts.NullPermissions = true
	// Enable diagnostics logging
	if !*quiet {
		opts.Logger = log.New(os.Stderr, "", 0)
	}
	server, err := fs.Mount(flag.Arg(1), loopbackRoot, opts)
	if err != nil {
		log.Fatalf("Mount fail: %v\n", err)
	}
	if !*quiet {
		fmt.Println("Mounted!")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		s := <-c
		log.Printf("Got signal: %s, unmounting and exiting", s)
		server.Unmount()
	}()

	server.Wait()
}
