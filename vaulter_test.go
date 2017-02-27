package vaulter

import (
	"errors"
	"fmt"
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

type StubMounter struct {
	path string
	mi   *vault.MountInput
}

func (s *StubMounter) Mount(p string, mi *vault.MountInput) error {
	s.path = p
	s.mi = mi
	return nil
}

func TestMountCubbyhole(t *testing.T) {
	sm := &StubMounter{}
	err := Mount(sm, "cubbyhole/", &MountConfiguration{
		Type:        "cubbyhole",
		Description: "A cubbyhole mount for iRODS configs",
	})
	if err != nil {
		t.Error(err)
	}
	if sm.mi.Type != "cubbyhole" {
		t.Errorf("type was %s instead of %s", sm.mi.Type, "cubbyhole")
	}
	if sm.mi.Description != "A cubbyhole mount for iRODS configs" {
		t.Errorf("description was %s instead of '%s'", sm.mi.Description, "A cubbyhole mount for iRODS configs")
	}
}

func TestMountPKI(t *testing.T) {
	sm := &StubMounter{}
	err := Mount(sm, "pki/", &MountConfiguration{
		Type:        "pki",
		Description: "A pki backend for HTCondor jobs",
	})
	if err != nil {
		t.Error(err)
	}
	if sm.mi.Type != "pki" {
		t.Errorf("type was %s instead of %s", sm.mi.Type, "pki")
	}
	if sm.mi.Description != "A pki backend for HTCondor jobs" {
		t.Errorf("description was %s instead of '%s'", sm.mi.Description, "A pki backend for HTCondor jobs")
	}
}

type StubMountLister struct {
	returnMiss bool
	returnErr  bool
}

func (s *StubMountLister) ListMounts() (map[string]*vault.MountOutput, error) {
	if s.returnErr {
		return nil, errors.New("test error")
	}
	if s.returnMiss {
		return map[string]*vault.MountOutput{
			"cubbyhole2/": &vault.MountOutput{},
			"pki2/":       &vault.MountOutput{},
		}, nil
	}
	return map[string]*vault.MountOutput{
		"cubbyhole/": &vault.MountOutput{},
		"pki/":       &vault.MountOutput{},
	}, nil
}

func TestIsCubbyholeMounted(t *testing.T) {
	lister := &StubMountLister{}
	m, err := IsMounted(lister, "cubbyhole/")
	if err != nil {
		t.Error(err)
	}
	if !m {
		t.Error("the cubbyhole mount was not found")
	}

	lister = &StubMountLister{
		returnMiss: true,
	}
	m, err = IsMounted(lister, "cubbyhole/")
	if err != nil {
		t.Error(err)
	}
	if m {
		t.Error("the cubbyhole mount was found")
	}

	lister = &StubMountLister{
		returnErr: true,
	}
	m, err = IsMounted(lister, "cubbyhole/")
	if err == nil {
		t.Error(err)
	}
	if m {
		t.Error("the cubbyhole mount was found")
	}
}

func TestIsPKIMounted(t *testing.T) {
	lister := &StubMountLister{}
	m, err := IsMounted(lister, "pki/")
	if err != nil {
		t.Error(err)
	}
	if !m {
		t.Error("the pki backend was not found")
	}

	lister = &StubMountLister{
		returnMiss: true,
	}
	m, err = IsMounted(lister, "pki/")
	if err != nil {
		t.Error(err)
	}
	if m {
		t.Error("the pki backend mount was found")
	}

	lister = &StubMountLister{
		returnErr: true,
	}
	m, err = IsMounted(lister, "pki/")
	if err == nil {
		t.Error(err)
	}
	if m {
		t.Error("the pki backend mount was found")
	}
}

type StubMountConfigGetter struct {
	path string
}

func (s *StubMountConfigGetter) MountConfig(path string) (*vault.MountConfigOutput, error) {
	s.path = path
	return &vault.MountConfigOutput{}, nil
}

func TestPKIMountConfig(t *testing.T) {
	sg := &StubMountConfigGetter{}
	mo, err := MountConfig(sg, "pki/")
	if err != nil {
		t.Error(err)
	}
	if mo == nil {
		t.Error("MountConfigOutput was nil")
	}
	if sg.path != "pki/" {
		t.Errorf("path was '%s' instead of 'pki/'", sg.path)
	}
}

type StubCubbyholeWriter struct {
	cfg         *vault.Config
	token       string
	path        string
	data        map[string]interface{}
	clientError bool
	writeError  bool
}

func (w *StubCubbyholeWriter) GetConfig() *vault.Config {
	return w.cfg
}

func (w *StubCubbyholeWriter) NewClient(cfg *vault.Config) (*vault.Client, error) {
	w.cfg = cfg
	if w.clientError {
		return nil, errors.New("client error")
	}
	return &vault.Client{}, nil
}

func (w *StubCubbyholeWriter) SetToken(client *vault.Client, token string) {
	w.token = token
}

func (w *StubCubbyholeWriter) Write(client *vault.Client, token string, data map[string]interface{}) (*vault.Secret, error) {
	w.data = data
	secret := &vault.Secret{}
	if w.writeError {
		return secret, errors.New("write error")
	}
	return secret, nil
}

func TestWriteMount1(t *testing.T) {
	sw := &StubCubbyholeWriter{}
	err := WriteMount(sw, fmt.Sprintf("cubbyhole/%s", "token"), "token", map[string]interface{}{
		"irods-config": "content",
	})
	if err != nil {
		t.Error(err)
	}

	sw = &StubCubbyholeWriter{clientError: true}
	err = WriteMount(sw, fmt.Sprintf("cubbyhole/%s", "token"), "token", map[string]interface{}{
		"irods-config": "content",
	})
	if err == nil {
		t.Error("err was nil")
	}

	sw = &StubCubbyholeWriter{writeError: true}
	err = WriteMount(sw, fmt.Sprintf("cubbyhole/%s", "token"), "token", map[string]interface{}{
		"irods-config": "content",
	})
	if err == nil {
		t.Error("err was nil")
	}
}

type StubCubbyholeReader struct {
	cfg            *vault.Config
	token          string
	path           string
	data           map[string]interface{}
	clientError    bool
	readError      bool
	secretError    bool
	dataError      bool
	noConfigError  bool
	badConfigError bool
}

func (r *StubCubbyholeReader) GetConfig() *vault.Config {
	return r.cfg
}

func (r *StubCubbyholeReader) NewClient(cfg *vault.Config) (*vault.Client, error) {
	r.cfg = cfg
	if r.clientError {
		return nil, errors.New("client error")
	}
	return &vault.Client{}, nil
}

func (r *StubCubbyholeReader) SetToken(client *vault.Client, token string) {
	r.token = token
}

func (r *StubCubbyholeReader) Read(client *vault.Client, path string) (*vault.Secret, error) {
	if r.readError {
		return nil, errors.New("read error")
	}
	if r.secretError {
		return nil, nil
	}
	if r.dataError {
		return &vault.Secret{}, nil
	}
	if r.noConfigError {
		return &vault.Secret{
			Data: map[string]interface{}{},
		}, nil
	}
	if r.badConfigError {
		return &vault.Secret{
			Data: map[string]interface{}{
				"irods-config": nil,
			},
		}, nil
	}
	r.path = path
	retval := &vault.Secret{
		Data: map[string]interface{}{
			"irods-config": "foo",
		},
	}
	return retval, nil
}

func TestReadFromCubbyhole(t *testing.T) {
	sr := &StubCubbyholeReader{}
	s, err := ReadMount(sr, fmt.Sprintf("cubbyhole/%s", "token"), "token")
	if err != nil {
		t.Error(err)
	}
	if s == nil {
		t.Error("secret was nil")
	}
	v, ok := s["irods-config"]
	if !ok {
		t.Errorf("counldn't find the 'irods-config' in the data map")
	}
	if v != "foo" {
		t.Errorf("secret was '%s' instead of 'foo'", s)
	}

	sr = &StubCubbyholeReader{
		clientError: true,
	}
	s, err = ReadMount(sr, fmt.Sprintf("cubbyhole/%s", "token"), "token")
	if err == nil {
		t.Error(err)
	}
	if s != nil {
		t.Error("secret was not nil after a client creation error")
	}

	sr = &StubCubbyholeReader{
		secretError: true,
	}
	s, err = ReadMount(sr, fmt.Sprintf("cubbyhole/%s", "token"), "token")
	if err == nil {
		t.Error(err)
	}
	if s != nil {
		t.Error("secret was not empty after a client creation error")
	}

	sr = &StubCubbyholeReader{
		readError: true,
	}
	s, err = ReadMount(sr, fmt.Sprintf("cubbyhole/%s", "token"), "token")
	if err == nil {
		t.Error(err)
	}
	if s != nil {
		t.Error("secret was not empty after a client creation error")
	}

	sr = &StubCubbyholeReader{
		dataError: true,
	}
	s, err = ReadMount(sr, fmt.Sprintf("cubbyhole/%s", "token"), "token")
	if err == nil {
		t.Error(err)
	}
	if s != nil {
		t.Error("secret was not empty after a client creation error")
	}
}

type StubPKIChecker struct {
	cfg           *vault.Config
	token         string
	path          string
	data          map[string]interface{}
	clientError   bool
	writeError    bool
	notFoundError bool
}

func (w *StubPKIChecker) GetConfig() *vault.Config {
	return w.cfg
}

func (w *StubPKIChecker) NewClient(cfg *vault.Config) (*vault.Client, error) {
	w.cfg = cfg
	if w.clientError {
		return nil, errors.New("client error")
	}
	return &vault.Client{}, nil
}

func (w *StubPKIChecker) SetToken(client *vault.Client, token string) {
	w.token = token
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
	hasCert, err := HasRootCert(cw, "example-dot-com", "test.example.com")
	if err != nil {
		t.Error(err)
	}
	if hasCert {
		t.Error("cert was found when it should be missing")
	}

	cw = &StubPKIChecker{writeError: true}
	hasCert, err = HasRootCert(cw, "example-dot-com", "test.example.com")
	if err == nil {
		t.Error("err was nil when it should have been set")
	}
	if hasCert {
		t.Error("cert was found when it should be missing")
	}

	cw = &StubPKIChecker{clientError: true}
	hasCert, err = HasRootCert(cw, "example-dot-com", "test.example.com")
	if err == nil {
		t.Error("err was nil when it should have been set")
	}
	if hasCert {
		t.Error("cert was found when it should be missing")
	}

	cw = &StubPKIChecker{}
	hasCert, err = HasRootCert(cw, "example-dot-com", "test.example.com")
	if err != nil {
		t.Error(err)
	}
	if !hasCert {
		t.Error("cert was not found when it should be present")
	}
}

type StubRoller struct {
	path       string
	data       map[string]interface{}
	writeError bool
	readError  bool
}

func (r *StubRoller) Client() *vault.Client {
	return &vault.Client{}
}

func (r *StubRoller) Write(client *vault.Client, token string, data map[string]interface{}) (*vault.Secret, error) {
	r.data = data
	secret := &vault.Secret{}
	if r.writeError {
		return nil, errors.New("write error")
	}
	return secret, nil
}

func (r *StubRoller) Read(client *vault.Client, path string) (*vault.Secret, error) {
	if r.readError {
		return nil, errors.New("read error")
	}
	r.path = path
	retval := &vault.Secret{
		Data: map[string]interface{}{
			"allowed_domains":  "foo.com",
			"allow_subdomains": true,
		},
	}
	return retval, nil
}

func TestCreateRole(t *testing.T) {
	sr := &StubRoller{}
	secret, err := CreateRole(sr, "foo", "foo.com", true)
	if err != nil {
		t.Error(err)
	}
	if secret == nil {
		t.Error("secret is nil")
	}

	sr = &StubRoller{writeError: true}
	secret, err = CreateRole(sr, "foo", "foo.com", true)
	if err == nil {
		t.Error(err)
	}
	if secret != nil {
		t.Error("secret is nil")
	}
}

func TestHasRole(t *testing.T) {
	sr := &StubRoller{}
	hasRole, err := HasRole(sr, "foo", "foo.com", true)
	if err != nil {
		t.Error(err)
	}
	if !hasRole {
		t.Error("hasRole was false")
	}
}

type StubMountReaderWriter struct {
	path       string
	data       map[string]interface{}
	writeError bool
	readError  bool
}

func (r *StubMountReaderWriter) Client() *vault.Client {
	return &vault.Client{}
}

func (r *StubMountReaderWriter) Write(client *vault.Client, token string, data map[string]interface{}) (*vault.Secret, error) {
	r.data = data
	secret := &vault.Secret{}
	if r.writeError {
		return nil, errors.New("write error")
	}
	return secret, nil
}

func (r *StubMountReaderWriter) Read(client *vault.Client, path string) (*vault.Secret, error) {
	if r.readError {
		return nil, errors.New("read error")
	}
	r.path = path
	retval := &vault.Secret{
		Data: map[string]interface{}{
			"allowed_domains":  "foo.com",
			"allow_subdomains": "true",
		},
	}
	return retval, nil
}

func TestGeneratePKICert(t *testing.T) {
	mrw := &StubMountReaderWriter{}
	secret, err := GeneratePKICert(mrw, "foo", "foo.com")
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
