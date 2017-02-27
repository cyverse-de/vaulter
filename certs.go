package vaulter

import (
	"fmt"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// Revoker is an interface for objects that can be used to revoke a certificate.
type Revoker interface {
	Revoke(c *vault.Client, id string) error
}

// PKIChecker defines the interface for checking to see if root PKI cert is
// configured.
type PKIChecker interface {
	ClientCreator
	ConfigGetter
	MountWriter // this is not a mistake.
}

// PKIRevoker defines an interface for revoking a cert.
type PKIRevoker interface {
	ClientGetter
	Revoker
}

// GeneratePKICert returns a new PKI cert
func GeneratePKICert(r MountReaderWriter, roleName, commonName string) (*vault.Secret, error) {
	client := r.Client()
	writePath := fmt.Sprintf("pki/issue/%s", roleName)
	data := map[string]interface{}{
		"common_name": commonName,
	}
	return r.Write(client, writePath, data)
}

// RevokePKICert revokes a PKI cert
func RevokePKICert(r PKIRevoker, id string) error {
	client := r.Client()
	return r.Revoke(client, id)
}

// HasRootCert returns true if a cert for the provided role and common-name
// already exists. The current process is a hack. We attempt to generate a cert,
// if the attempt succeeds then the root cert exists.
func HasRootCert(m PKIChecker, role, commonName string) (bool, error) {
	var (
		client *vault.Client
		err    error
	)
	if client, err = m.NewClient(m.GetConfig()); err != nil {
		return false, err
	}
	writePath := fmt.Sprintf("pki/issue/%s", role)
	_, err = m.Write(client, writePath, map[string]interface{}{
		"common_name": commonName,
	})
	if err != nil {
		if strings.HasSuffix(err.Error(), "backend must be configured with a CA certificate/key") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
