package main

import (
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

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hnakamur/agefs"
	"github.com/hnakamur/agefs/internal/ageutil"
)

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

	orig := flag.Arg(0)
	mountpoint := flag.Arg(1)

	identities, err := ageutil.ParseIdentitiesFile(*privName)
	if err != nil {
		fmt.Printf("failed to load private key: %s", err)
		os.Exit(1)
	}

	ignoreFilename := filepath.Join(orig, ".ageignore")
	shouldEncrypt, err := agefs.ReadIgnoreFile(ignoreFilename)
	if err != nil {
		log.Fatalf("read .ageignore file (%s): %v\n", ignoreFilename, err)
	}

	agefsRoot, err := agefs.NewRoot(orig, identities, shouldEncrypt)
	if err != nil {
		log.Fatalf("create agefs root node at (%s): %v\n", orig, err)
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
	opts.MountOptions.Name = "agefs"
	// Leave file permissions on "000" files as-is
	opts.NullPermissions = true
	// Enable diagnostics logging
	if !*quiet {
		opts.Logger = log.New(os.Stderr, "", 0)
	}
	server, err := fs.Mount(mountpoint, agefsRoot, opts)
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
