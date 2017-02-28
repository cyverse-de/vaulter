package vaulter

import (
	"errors"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

type StubTokener struct {
	returnError bool
}

func (s *StubTokener) Token() *vault.TokenAuth {
	return &vault.TokenAuth{}
}

func (s *StubTokener) CreateToken(ta *vault.TokenAuth, opts *vault.TokenCreateRequest) (*vault.Secret, error) {
	if s.returnError {
		return nil, errors.New("test error")
	}
	return &vault.Secret{
		Auth: &vault.SecretAuth{
			ClientToken: "foo",
		},
	}, nil
}

func TestChildToken(t *testing.T) {
	st := &StubTokener{}
	tk, err := ChildToken(st)
	if err != nil {
		t.Error(err)
	}
	if tk == "" {
		t.Error("token was empty")
	}
	if tk != "foo" {
		t.Errorf("token was %s rather than %s", tk, "foo")
	}

	st = &StubTokener{
		returnError: true,
	}
	tk, err = ChildToken(st)
	if err == nil {
		t.Error("error was nil")
	}
	if tk != "" {
		t.Errorf("tk was %s instead of being empty", tk)
	}
}
