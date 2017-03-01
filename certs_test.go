package vaulter

import (
	"errors"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

type StubPKIChecker struct {
	cfg           *vault.Config
	token         string
	path          string
	data          map[string]interface{}
	clientError   bool
	writeError    bool
	notFoundError bool
}

func (w *StubPKIChecker) Client() *vault.Client {
	return &vault.Client{}
}

func (w *StubPKIChecker) Write(client *vault.Client, token string, data map[string]interface{}) (*vault.Secret, error) {
	w.data = data
	secret := &vault.Secret{}
	if w.notFoundError {
		return nil, errors.New("backend must be configured with a CA certificate/key")
	}
	if w.writeError {
		return secret, errors.New("write error")
	}
	return secret, nil
}

func TestHasRootCert(t *testing.T) {
	cw := &StubPKIChecker{notFoundError: true}
	hasCert, err := HasRootCert(cw, "pki", "example-dot-com", "test.example.com")
	if err != nil {
		t.Error(err)
	}
	if hasCert {
		t.Error("cert was found when it should be missing")
	}

	cw = &StubPKIChecker{writeError: true}
	hasCert, err = HasRootCert(cw, "pki", "example-dot-com", "test.example.com")
	if err == nil {
		t.Error("err was nil when it should have been set")
	}
	if hasCert {
		t.Error("cert was found when it should be missing")
	}

	cw = &StubPKIChecker{}
	hasCert, err = HasRootCert(cw, "pki", "example-dot-com", "test.example.com")
	if err != nil {
		t.Error(err)
	}
	if !hasCert {
		t.Error("cert was not found when it should be present")
	}
}

func TestGeneratePKICert(t *testing.T) {
	mrw := &StubMountReaderWriter{}
	secret, err := GeneratePKICert(mrw, "pki", "foo", "foo.com")
	if err != nil {
		t.Error(err)
	}
	if secret == nil {
		t.Error("secret is nil")
	}
	if mrw.data["common_name"] != "foo.com" {
		t.Errorf("common_name was '%s' instead of 'foo.com'", mrw.data["common_name"])
	}
}

type StubPKIRevoker struct {
	certID string
}

func (r *StubPKIRevoker) Client() *vault.Client {
	return &vault.Client{}
}

func (r *StubPKIRevoker) Revoke(client *vault.Client, id string) error {
	r.certID = id
	return nil
}

func TestRevokePKICert(t *testing.T) {
	rv := &StubPKIRevoker{}
	err := RevokePKICert(rv, "foo")
	if err != nil {
		t.Error(err)
	}
	if rv.certID != "foo" {
		t.Errorf("clientID was '%s' instead of 'foo'", rv.certID)
	}
}
