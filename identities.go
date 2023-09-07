package agefs

import (
	"filippo.io/age"
	"github.com/hnakamur/agefs/internal/ageutil"
)

// ParseIdentitiesFileOption is the option type for [ParseIdentitiesFile].
type ParseIdentitiesFileOption = ageutil.ParseIdentitiesFileOption

// WithPassphrase sets a function to get the passphrase for decrypting the identity file.
func WithPassphrase(fn func() (string, error)) ParseIdentitiesFileOption {
	return ageutil.WithPassphrase(fn)
}

// ParseIdentitiesFile parses a file that contains age or SSH keys. It returns
// one or more of *age.X25519Identity, *agessh.RSAIdentity, *agessh.Ed25519Identity,
// *agessh.EncryptedSSHIdentity, or *EncryptedIdentity.
func ParseIdentitiesFile(name string, opts ...ParseIdentitiesFileOption) ([]age.Identity, error) {
	return ageutil.ParseIdentitiesFile(name, opts...)
}
