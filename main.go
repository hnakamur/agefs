package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime/pprof"
	"syscall"
	"time"
	"unsafe"

	"filippo.io/age"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hnakamur/ageutil"
)

type AgeFSRoot struct {
	fs.LoopbackRoot
	identities []age.Identity
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

type AgeFSFile struct {
	fs.FileHandle
	// buf *bytes.Buffer
}

var _ = (fs.FileHandle)((*AgeFSFile)(nil))

// var _ = (fs.FileReleaser)((*AgeFSFile)(nil))
// var _ = (fs.FileGetattrer)((*AgeFSFile)(nil))
var _ = (fs.FileReader)((*AgeFSFile)(nil))

// var _ = (fs.FileWriter)((*AgeFSFile)(nil))
// var _ = (fs.FileGetlker)((*AgeFSFile)(nil))
// var _ = (fs.FileSetlker)((*AgeFSFile)(nil))
// var _ = (fs.FileSetlkwer)((*AgeFSFile)(nil))
// var _ = (fs.FileLseeker)((*AgeFSFile)(nil))
// var _ = (fs.FileFlusher)((*AgeFSFile)(nil))
// var _ = (fs.FileFsyncer)((*AgeFSFile)(nil))
// var _ = (fs.FileSetattrer)((*AgeFSFile)(nil))
// var _ = (fs.FileAllocater)((*AgeFSFile)(nil))

func NewAgeFSRoot(rootPath string, identities []age.Identity) (fs.InodeEmbedder, error) {
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
				return &AgeFSNode{
					LoopbackNode: fs.LoopbackNode{
						RootData: rootData,
					},
				}
			},
		},
		identities: identities,
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
	lf := NewAgeFSFile(f)
	return lf, 0, 0
}

// path returns the full path to the file in the underlying file
// system.
func (n *AgeFSNode) path() string {
	path := n.Path(n.Root())
	return filepath.Join(n.RootData.Path, path)
}

func NewAgeFSFile(fd int) *AgeFSFile {
	return &AgeFSFile{
		FileHandle: fs.NewLoopbackFile(fd),
	}
}

func (f *AgeFSFile) Read(ctx context.Context, buf []byte, off int64) (res fuse.ReadResult, errno syscall.Errno) {
	return f.FileHandle.(fs.FileReader).Read(ctx, buf, off)
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

	identities, err := ageutil.ParseSSHPrivateKeyFile(*privName)
	if err != nil {
		fmt.Printf("failed to load private key: %s", err)
		os.Exit(1)
	}
	log.Printf("identities=%+v", identities)

	orig := flag.Arg(0)
	loopbackRoot, err := NewAgeFSRoot(orig, identities)
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
