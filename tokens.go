package vaulter

import (
	"errors"

	vault "github.com/hashicorp/vault/api"
)

// Tokener is an interface for objects that can issue Vault tokens.
type Tokener interface {
	Token() *vault.TokenAuth
	CreateToken(ta *vault.TokenAuth, opts *vault.TokenCreateRequest) (*vault.Secret, error)
}

// ChildToken generates a new token that's a child of the one configured for the
// *AppVaulter vault client.
func ChildToken(t Tokener) (string, error) {
	opts := &vault.TokenCreateRequest{
		NumUses: 2, // one use is for writing to the cubbyhole
	}
	ta := t.Token()
	secret, err := t.CreateToken(ta, opts)
	if err != nil {
		return "", err
	}
	if secret.Auth == nil {
		return "", errors.New("SecretAuth was nil")
	}
	if secret.Auth.ClientToken == "" {
		return "", errors.New("ClientToken was empty")
	}
	return secret.Auth.ClientToken, nil
}
