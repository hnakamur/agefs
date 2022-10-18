package agefs

import (
	"filippo.io/age"
	"github.com/hnakamur/agefs/internal/ageutil"
)

// ParseIdentitiesFile parses a file that contains age or SSH keys. It returns
// one or more of *age.X25519Identity, *agessh.RSAIdentity, *agessh.Ed25519Identity,
// *agessh.EncryptedSSHIdentity, or *EncryptedIdentity.
func ParseIdentitiesFile(name string) ([]age.Identity, error) {
	return ageutil.ParseIdentitiesFile(name)
}
