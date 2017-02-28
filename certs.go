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

// CSRConfig contains configuration settings for generating a certificate
// signing request.
type CSRConfig struct {
	CommonName        string
	TTL               string
	KeyBits           int
	ExcludeCNFromSans bool // disables adding the common name to the list of subject alternative names
}

// ImportCert sets the signed cert for the backend mounted at the given path
// inside Vault.
func ImportCert(m MountReaderWriter, mountPath, certContents string) (*vault.Secret, error) {
	client := m.Client()
	path := fmt.Sprintf("%s/intermediate/set-signed", mountPath)
	data := map[string]interface{}{
		"certificate": certContents,
	}
	return m.Write(client, path, data)
}

// CSR generates a certificate signing request using the backend mounted at the
// provided directory.
func CSR(m MountReaderWriter, mountPath string, c *CSRConfig) (*vault.Secret, error) {
	var client *vault.Client
	client = m.Client()
	path := fmt.Sprintf("%s/intermediate/generate/internal", mountPath)
	data := map[string]interface{}{
		"common_name":          c.CommonName,
		"ttl":                  c.TTL,
		"key_bits":             c.KeyBits,
		"exclude_cn_from_sans": c.ExcludeCNFromSans,
	}
	return m.Write(client, path, data)
}

// ConfigCAAccess sets the issuing_certificates and crl_distribution_points URLs
// for the backend mounted at the given path.
func ConfigCAAccess(m MountReaderWriter, scheme, hostPort, mountPath string) (*vault.Secret, error) {
	var client *vault.Client
	client = m.Client()
	path := fmt.Sprintf("%s/config/urls", mountPath)
	data := map[string]interface{}{
		"issuing_certificates":    fmt.Sprintf("%s://%s/v1/%s/ca", scheme, hostPort, mountPath),
		"crl_distribution_points": fmt.Sprintf("%s://%s/v1/%s/crl", scheme, hostPort, mountPath),
	}
	return m.Write(client, path, data)
}
