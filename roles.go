package vaulter

import (
	"fmt"
	"strconv"

	vault "github.com/hashicorp/vault/api"
)

// CreateRole creates a new role.
func CreateRole(r MountReaderWriter, roleName, domains string, subdomains bool) (*vault.Secret, error) {
	client := r.Client()
	writePath := fmt.Sprintf("pki/roles/%s", roleName)
	data := map[string]interface{}{
		"allowed_domains":  domains,
		"allow_subdomains": strconv.FormatBool(subdomains),
	}
	return r.Write(client, writePath, data)
}

// HasRole returns true if the passed in role exists and has the same settings.
func HasRole(r MountReaderWriter, roleName, domains string, subdomains bool) (bool, error) {
	client := r.Client()
	readPath := fmt.Sprintf("pki/roles/%s", roleName)
	secret, err := r.Read(client, readPath)
	if err != nil {
		return false, err
	}
	if secret == nil {
		return false, nil
	}
	if secret.Data == nil {
		return false, nil
	}
	v, ok := secret.Data["allowed_domains"]
	if !ok {
		return false, nil
	}
	if v != domains {
		return false, nil
	}
	v, ok = secret.Data["allow_subdomains"]
	if !ok {
		return false, nil
	}
	if v != subdomains {
		fmt.Printf("v: %s\tsubdomains: %s\n", v, strconv.FormatBool(subdomains))
		return false, nil
	}
	return true, nil
}
