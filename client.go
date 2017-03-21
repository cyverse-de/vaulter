package vaulter

import vault "github.com/hashicorp/vault/api"

// ClientGetter is an interface for objects that need access to the Vault
// client.
type ClientGetter interface {
	Client() *vault.Client
}
