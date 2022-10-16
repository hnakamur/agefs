package ageutil

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/hnakamur/agefs/internal/ageutil/plugin"
	"golang.org/x/crypto/cryptobyte"
)

type gitHubRecipientError struct {
	username string
}

func (gitHubRecipientError) Error() string {
	return `"github:" recipients were removed from the design`
}

func parseRecipient(arg string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(arg, "age1") && strings.Count(arg, "1") > 1:
		return plugin.NewRecipient(arg, pluginTerminalUI)
	case strings.HasPrefix(arg, "age1"):
		return age.ParseX25519Recipient(arg)
	case strings.HasPrefix(arg, "ssh-"):
		return agessh.ParseRecipient(arg)
	case strings.HasPrefix(arg, "github:"):
		name := strings.TrimPrefix(arg, "github:")
		return nil, gitHubRecipientError{name}
	}

	return nil, fmt.Errorf("unknown recipient type: %q", arg)
}

func ParseRecipientsFile(name string) ([]age.Recipient, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open recipient file: %v", err)
	}
	defer f.Close()

	const recipientFileSizeLimit = 16 << 20 // 16 MiB
	const lineLengthLimit = 8 << 10         // 8 KiB, same as sshd(8)
	var recs []age.Recipient
	scanner := bufio.NewScanner(io.LimitReader(f, recipientFileSizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if len(line) > lineLengthLimit {
			return nil, fmt.Errorf("%q: line %d is too long", name, n)
		}
		r, err := parseRecipient(line)
		if err != nil {
			if t, ok := sshKeyType(line); ok {
				// Skip unsupported but valid SSH public keys with a warning.
				warningf("recipients file %q: ignoring unsupported SSH key of type %q at line %d", name, t, n)
				continue
			}
			// Hide the error since it might unintentionally leak the contents
			// of confidential files.
			return nil, fmt.Errorf("%q: malformed recipient at line %d", name, n)
		}
		recs = append(recs, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%q: failed to read recipients file: %v", name, err)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("%q: no recipients found", name)
	}
	return recs, nil
}

func sshKeyType(s string) (string, bool) {
	// TODO: also ignore options? And maybe support multiple spaces and tabs as
	// field separators like OpenSSH?
	fields := strings.Split(s, " ")
	if len(fields) < 2 {
		return "", false
	}
	key, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", false
	}
	k := cryptobyte.String(key)
	var typeLen uint32
	var typeBytes []byte
	if !k.ReadUint32(&typeLen) || !k.ReadBytes(&typeBytes, int(typeLen)) {
		return "", false
	}
	if t := fields[0]; t == string(typeBytes) {
		return t, true
	}
	return "", false
}
