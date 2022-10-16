package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"runtime/pprof"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hnakamur/agefs"
	"github.com/hnakamur/agefs/internal/ageutil"
	"github.com/urfave/cli/v2"
	"go.uber.org/multierr"
)

func main() {
	app := &cli.App{
		Name:        "agefs",
		Version:     Version(),
		Usage:       "CLI for mounting a FUSE filesystem with encryption/decryption files using age-encryption.org",
		Description: "agefs is an CLI for mounting agefs, generating keys",
		Commands: []*cli.Command{
			{
				Name:    "mount",
				Aliases: []string{"m"},
				Usage:   "mounting agefs filesystem (unmount when exits)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "identity",
						Aliases:  []string{"i"},
						Required: true,
						Usage:    "identity filename",
					},
					&cli.StringFlag{
						Name:     "src",
						Aliases:  []string{"s"},
						Required: true,
						Usage:    "source directory",
					},
					&cli.StringFlag{
						Name:     "mountpoint",
						Aliases:  []string{"m"},
						Required: true,
						Usage:    "mountpoint directory",
					},
					&cli.BoolFlag{
						Name:    "read-only",
						Aliases: []string{"r"},
						Usage:   "mount with readonly",
					},
					&cli.BoolFlag{
						Name:  "allow-other",
						Usage: "mount with -o allowother",
					},
					&cli.BoolFlag{
						Name:    "quiet",
						Aliases: []string{"q"},
						Usage:   "quiet",
					},
					&cli.BoolFlag{
						Name:    "debug",
						Aliases: []string{"d"},
						Usage:   "print debugging messages",
					},
					&cli.StringFlag{
						Name:  "cpu-profile",
						Usage: "write cpu profile to this file",
					},
					&cli.StringFlag{
						Name:  "mem-profile",
						Usage: "write memory profile to this file",
					},
				},
				Action: func(cCtx *cli.Context) error {
					return mountAction(
						cCtx.String("identity"),
						cCtx.String("src"),
						cCtx.String("mountpoint"),
						cCtx.Bool("read-only"),
						cCtx.Bool("allow-other"),
						cCtx.Bool("quiet"),
						cCtx.Bool("debug"),
						cCtx.String("cpu-profile"),
						cCtx.String("mem-profile"),
					)
				},
			},
			{
				Name:    "keygen",
				Aliases: []string{"k"},
				Usage:   "generate an identity file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "out",
						Aliases:  []string{"o"},
						Required: true,
						Usage:    "output filename",
					},
					&cli.BoolFlag{
						Name:    "encrypt",
						Aliases: []string{"e"},
						Value:   true,
						Usage:   "encrypt the identity file",
					},
					&cli.BoolFlag{
						Name:    "passphrase",
						Aliases: []string{"p"},
						Usage:   "show prompt for passphrase to encrypt the identity file",
					},
				},
				Action: func(cCtx *cli.Context) error {
					return keygenAction(
						cCtx.String("out"),
						cCtx.Bool("encrypt"),
						cCtx.Bool("passphrase"),
					)
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %s\n", err)
		os.Exit(2)
	}
}

func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(devel)"
	}
	return info.Main.Version
}

func mountAction(identityFilename, srcDir, mountpoint string,
	readonly, allowOther, quiet, debug bool,
	cpuProfile, memProfile string) (err error) {

	if cpuProfile != "" {
		if !quiet {
			fmt.Printf("Writing cpu profile to %s\n", cpuProfile)
		}
		f, err := os.Create(cpuProfile)
		if err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	if memProfile != "" {
		if !quiet {
			log.Printf("send SIGUSR1 to %d to dump memory profile", os.Getpid())
		}
		profSig := make(chan os.Signal, 1)
		signal.Notify(profSig, syscall.SIGUSR1)
		go writeMemProfile(memProfile, profSig)
	}
	if cpuProfile != "" || memProfile != "" {
		if !quiet {
			fmt.Printf("Note: You must unmount gracefully, otherwise the profile file(s) will stay empty!\n")
		}
	}

	identities, err := ageutil.ParseIdentitiesFile(identityFilename)
	if err != nil {
		fmt.Printf("failed to load private key: %s", err)
		os.Exit(1)
	}

	ignoreFilename := filepath.Join(srcDir, ".ageignore")
	shouldEncrypt, err := agefs.ReadIgnoreFile(ignoreFilename)
	if err != nil {
		log.Fatalf("read .ageignore file (%s): %v\n", ignoreFilename, err)
	}

	agefsRoot, err := agefs.NewRoot(srcDir, identities, shouldEncrypt)
	if err != nil {
		log.Fatalf("create agefs root node at (%s): %v\n", srcDir, err)
	}

	sec := time.Second
	opts := &fs.Options{
		// These options are to be compatible with libfuse defaults,
		// making benchmarking easier.
		AttrTimeout:  &sec,
		EntryTimeout: &sec,
	}
	opts.Debug = debug
	opts.AllowOther = allowOther
	if opts.AllowOther {
		// Make the kernel check file permissions for us
		opts.MountOptions.Options = append(opts.MountOptions.Options, "default_permissions")
	}
	if readonly {
		opts.MountOptions.Options = append(opts.MountOptions.Options, "ro")
	}
	// First column in "df -T": original dir
	opts.MountOptions.Options = append(opts.MountOptions.Options, "fsname="+srcDir)
	// Second column in "df -T" will be shown as "fuse." + Name
	opts.MountOptions.Name = "agefs"
	// Leave file permissions on "000" files as-is
	opts.NullPermissions = true
	// Enable diagnostics logging
	if !quiet {
		opts.Logger = log.New(os.Stderr, "", 0)
	}
	server, err := fs.Mount(mountpoint, agefsRoot, opts)
	if err != nil {
		log.Fatalf("Mount fail: %v\n", err)
	}
	if !quiet {
		opts.Logger.Println("Mounted!")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-c
		if !quiet {
			opts.Logger.Printf("Got signal: %s, unmounting and exiting", s)
		}
		server.Unmount()
	}()

	server.Wait()

	return nil
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

func keygenAction(outFilename string, encryptKey, usePassphrase bool) (err error) {
	if usePassphrase && !encryptKey {
		return errors.New("option --passphrase must not be specified when option --encrypt is true")
	}

	var passphrase string
	if encryptKey {
		if usePassphrase {
			if passphrase, err = ageutil.PassphrasePromptForEncryption(); err != nil {
				return err
			}
		} else {
			if passphrase, err = ageutil.GenerateAndPrintPassphrase(); err != nil {
				return err
			}
		}
	}

	k, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}

	outFile, err := os.OpenFile(outFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("cannot create output file, filename=%s, err=%v", outFilename, err)
	}
	defer func() {
		err = multierr.Append(err, outFile.Close())
	}()

	if fi, err := outFile.Stat(); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0004 != 0 {
		return errors.New("writing secret key to a world-readable file")
	}

	bw := bufio.NewWriter(outFile)

	var out io.Writer
	var ew io.WriteCloser
	if passphrase == "" {
		out = bw
	} else {
		r, err := age.NewScryptRecipient(passphrase)
		if err != nil {
			return err
		}
		ew, err = ageutil.NewEncryptingWriter([]age.Recipient{r}, bw, true)
		if err != nil {
			return err
		}
		out = ew
	}

	if _, err := fmt.Fprintf(out, "# created: %s\n", time.Now().Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "# public key: %s\n", k.Recipient()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "%s\n", k); err != nil {
		return err
	}
	if ew != nil {
		if err := ew.Close(); err != nil {
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := outFile.Sync(); err != nil {
		return err
	}

	pubKeyFilename := outFilename + ".pub"
	pubKeyData := fmt.Sprintf("%s\n", k.Recipient())
	if err := os.WriteFile(pubKeyFilename, []byte(pubKeyData), 0600); err != nil {
		return err
	}

	return nil
}
