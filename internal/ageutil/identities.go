package ageutil

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"github.com/hnakamur/agefs/internal/ageutil/plugin"
	"golang.org/x/crypto/ssh"
)

// ParseIdentitiesFile parses a file that contains age or SSH keys. It returns
// one or more of *age.X25519Identity, *agessh.RSAIdentity, *agessh.Ed25519Identity,
// *agessh.EncryptedSSHIdentity, or *EncryptedIdentity.
func ParseIdentitiesFile(name string) ([]age.Identity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	b := bufio.NewReader(f)
	p, _ := b.Peek(14) // length of "age-encryption" and "-----BEGIN AGE"
	peeked := string(p)

	switch {
	// An age encrypted file, plain or armored.
	case peeked == "age-encryption" || peeked == "-----BEGIN AGE":
		var r io.Reader = b
		if peeked == "-----BEGIN AGE" {
			r = armor.NewReader(r)
		}
		const privateKeySizeLimit = 1 << 24 // 16 MiB
		contents, err := io.ReadAll(io.LimitReader(r, privateKeySizeLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		if len(contents) == privateKeySizeLimit {
			return nil, fmt.Errorf("failed to read %q: file too long", name)
		}
		return []age.Identity{&encryptedIdentity{
			Contents: contents,
			Passphrase: func() (string, error) {
				pass, err := readSecret(fmt.Sprintf("Enter passphrase for identity file %q:", name))
				if err != nil {
					return "", fmt.Errorf("could not read passphrase: %v", err)
				}
				return string(pass), nil
			},
			NoMatchWarning: func() {
				warningf("encrypted identity file %q didn't match file's recipients", name)
			},
		}}, nil

	// Another PEM file, possibly an SSH private key.
	case strings.HasPrefix(peeked, "-----BEGIN"):
		const privateKeySizeLimit = 1 << 14 // 16 KiB
		contents, err := io.ReadAll(io.LimitReader(b, privateKeySizeLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		if len(contents) == privateKeySizeLimit {
			return nil, fmt.Errorf("failed to read %q: file too long", name)
		}
		return parseSSHIdentity(name, contents)

	// An unencrypted age identity file.
	default:
		ids, err := parseIdentities(b)
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		return ids, nil
	}
}

func parseIdentity(s string) (age.Identity, error) {
	switch {
	case strings.HasPrefix(s, "AGE-PLUGIN-"):
		return plugin.NewIdentity(s, pluginTerminalUI)
	case strings.HasPrefix(s, "AGE-SECRET-KEY-1"):
		return age.ParseX25519Identity(s)
	default:
		return nil, fmt.Errorf("unknown identity type")
	}
}

// parseIdentities is like age.ParseIdentities, but supports plugin identities.
func parseIdentities(f io.Reader) ([]age.Identity, error) {
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	var ids []age.Identity
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		i, err := parseIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		ids = append(ids, i)

	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read secret keys file: %v", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no secret keys found")
	}
	return ids, nil
}

func parseSSHIdentity(name string, pemBytes []byte) ([]age.Identity, error) {
	id, err := agessh.ParseIdentity(pemBytes)
	if sshErr, ok := err.(*ssh.PassphraseMissingError); ok {
		pubKey := sshErr.PublicKey
		if pubKey == nil {
			pubKey, err = readPubFile(name)
			if err != nil {
				return nil, err
			}
		}
		passphrasePrompt := func() ([]byte, error) {
			pass, err := readSecret(fmt.Sprintf("Enter passphrase for %q:", name))
			if err != nil {
				return nil, fmt.Errorf("could not read passphrase for %q: %v", name, err)
			}
			return pass, nil
		}
		i, err := agessh.NewEncryptedSSHIdentity(pubKey, pemBytes, passphrasePrompt)
		if err != nil {
			return nil, err
		}
		return []age.Identity{i}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}

	return []age.Identity{id}, nil
}

func readPubFile(name string) (ssh.PublicKey, error) {
	if name == "-" {
		return nil, fmt.Errorf(`failed to obtain public key for "-" SSH key

Use a file for which the corresponding ".pub" file exists, or convert the private key to a modern format with "ssh-keygen -p -m RFC4716"`)
	}
	f, err := os.Open(name + ".pub")
	if err != nil {
		return nil, fmt.Errorf(`failed to obtain public key for %q SSH key: %v

Ensure %q exists, or convert the private key %q to a modern format with "ssh-keygen -p -m RFC4716"`, name, err, name+".pub", name)
	}
	defer f.Close()
	contents, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name+".pub", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", name+".pub", err)
	}
	return pubKey, nil
}

func IdentitiesToRecipients(ids []age.Identity) ([]age.Recipient, error) {
	var recipients []age.Recipient
	for _, id := range ids {
		switch id := id.(type) {
		case *age.X25519Identity:
			recipients = append(recipients, id.Recipient())
		case *plugin.Identity:
			recipients = append(recipients, id.Recipient())
		case *agessh.RSAIdentity:
			recipients = append(recipients, id.Recipient())
		case *agessh.Ed25519Identity:
			recipients = append(recipients, id.Recipient())
		case *agessh.EncryptedSSHIdentity:
			recipients = append(recipients, id.Recipient())
		case *encryptedIdentity:
			r, err := id.Recipients()
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, r...)
		default:
			return nil, fmt.Errorf("unexpected identity type: %T", id)
		}
	}
	return recipients, nil
}
