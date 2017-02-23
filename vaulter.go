package vaulter

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// Tokener is an interface for objects that can issue Vault tokens.
type Tokener interface {
	Token() *vault.TokenAuth
	CreateToken(ta *vault.TokenAuth, opts *vault.TokenCreateRequest) (*vault.Secret, error)
}

// Mounter is an interface for objects that can mount Vault backends.
type Mounter interface {
	Mount(path string, m *vault.MountInput) error
}

// MountLister is an interface for objects that can list mounted Vault backends.
type MountLister interface {
	ListMounts() (map[string]*vault.MountOutput, error)
}

// MountConfigGetter is an interface for objects that can get the configuration
// for a mount in Vault.
type MountConfigGetter interface {
	MountConfig(path string) (*vault.MountConfigOutput, error)
}

// MountTuner is an interface for objects that need to configure a mount in
// Vault.
type MountTuner interface {
	TuneMount(path string, input vault.MountConfigInput) error
}

// ConfigGetter is an interface for objects that need access to the
// *vault.Config.
type ConfigGetter interface {
	GetConfig() *vault.Config
}

// ConfigSetter is an interface for objects that need to set the *vault.Config
// for an underlying client.
type ConfigSetter interface {
	SetConfig(c *vault.Config)
}

// Configurer is an interface for objects that can configure a Vault client.
type Configurer interface {
	DefaultConfig() *vault.Config
	ConfigureTLS(t *vault.TLSConfig) error
}

// ClientCreator is an interface for objects that can create new Vault clients.
type ClientCreator interface {
	NewClient(c *vault.Config) (*vault.Client, error)
}

// ClientGetter is an interface for objects that need access to the Vault
// client.
type ClientGetter interface {
	Client() *vault.Client
}

// ClientSetter is an interface for objects that need to set their internal
// client value.
type ClientSetter interface {
	SetClient(c *vault.Client)
}

// TokenSetter is an interface for objects that can set the root token for Vault
// clients.
type TokenSetter interface {
	SetToken(c *vault.Client, t string)
}

// MountWriter is an interface for objects that can write to a path in a Vault
// backend.
type MountWriter interface {
	Write(c *vault.Client, path string, data map[string]interface{}) (*vault.Secret, error)
}

// MountReader is an interface for objectst that can read data from a path in a
// Vault backend.
type MountReader interface {
	Read(c *vault.Client, path string) (*vault.Secret, error)
}

// CubbyholeWriter defines the interface for writing data to a cubbyhole.
type CubbyholeWriter interface {
	ClientCreator
	ConfigGetter
	TokenSetter
	MountWriter
}

// CubbyholeReader defines the interface for reading data from a cubbyhole
type CubbyholeReader interface {
	ClientCreator
	ConfigGetter
	TokenSetter
	MountReader
}

// PKIChecker defines the interface for checking to see if root PKI cert is
// configured.
type PKIChecker interface {
	ClientCreator
	ConfigGetter
	MountWriter // this is not a mistake.
}

// Roller defines an interface for doing role related operations.
type Roller interface {
	ClientGetter
	MountWriter
	MountReader
}

// Vaulter defines the lower-level interactions with vault so that they can be
// stubbed out in unit tests.
type Vaulter interface {
	Tokener
	Mounter
	MountConfigGetter
	MountLister
	Configurer
	ConfigGetter
	ConfigSetter
	ClientCreator
	ClientSetter
	ClientGetter
	TokenSetter
	MountWriter
	MountReader
}

// VaultAPI provides an implementation of the Vaulter interface that can
// actually hit the Vault API.
type VaultAPI struct {
	client *vault.Client
	cfg    *vault.Config
}

// Token returns a new Vault token.
func (v *VaultAPI) Token() *vault.TokenAuth {
	return v.client.Auth().Token()
}

// CreateToken returns a new child or orphan token.
func (v *VaultAPI) CreateToken(ta *vault.TokenAuth, opts *vault.TokenCreateRequest) (*vault.Secret, error) {
	return ta.Create(opts)
}

// Mount uses the Vault API to mount a backend at a path.
func (v *VaultAPI) Mount(path string, mi *vault.MountInput) error {
	sys := v.client.Sys()
	return sys.Mount(path, mi)
}

// MountConfig uses the VaultAPI to get the config for the passed in mount
// point.
func (v *VaultAPI) MountConfig(path string) (*vault.MountConfigOutput, error) {
	sys := v.client.Sys()
	return sys.MountConfig(path)
}

// TuneMount uses the VaultAPI to set the config for the passed in mount
// point.
func (v *VaultAPI) TuneMount(path string, in vault.MountConfigInput) error {
	sys := v.client.Sys()
	return sys.TuneMount(path, in)
}

// ListMounts lists the mounted Vault backends.
func (v *VaultAPI) ListMounts() (map[string]*vault.MountOutput, error) {
	sys := v.client.Sys()
	return sys.ListMounts()
}

// DefaultConfig returns a *vault.Config filled out with the default values.
// They're not just the Go zero values for data types.
func (v *VaultAPI) DefaultConfig() *vault.Config {
	return vault.DefaultConfig()
}

// ConfigureTLS sets up the passed in Vault config for TLS protected
// communication with Vault.
func (v *VaultAPI) ConfigureTLS(cfg *vault.Config, t *vault.TLSConfig) error {
	return cfg.ConfigureTLS(t)
}

// NewClient creates a new Vault client.
func (v *VaultAPI) NewClient(cfg *vault.Config) (*vault.Client, error) {
	return vault.NewClient(cfg)
}

// SetClient sets the value of the internal *vault.Client field.
func (v *VaultAPI) SetClient(c *vault.Client) {
	v.client = c
}

// Client gets the currently configured Vault client.
func (v *VaultAPI) Client() *vault.Client {
	return v.client
}

// GetConfig returns the *vault.Config instance used with the underlying client.
func (v *VaultAPI) GetConfig() *vault.Config {
	return v.cfg
}

// SetConfig sets the vault config that should be used with the underlying
// client. Is NOT called by NewClient().
func (v *VaultAPI) SetConfig(cfg *vault.Config) {
	v.cfg = cfg
}

// SetToken sets the root token for the provided vault client.
func (v *VaultAPI) SetToken(client *vault.Client, t string) {
	client.SetToken(t)
}

func (v *VaultAPI) Write(client *vault.Client, path string, data map[string]interface{}) (*vault.Secret, error) {
	logical := client.Logical()
	secret, err := logical.Write(path, data)
	return secret, err
}

func (v *VaultAPI) Read(client *vault.Client, path string) (*vault.Secret, error) {
	logical := client.Logical()
	return logical.Read(path)
}

// VaultAPIConfig contains the applications configuration settings.
type VaultAPIConfig struct {
	ParentToken string // Other tokens will be children of this token.
	Host        string // The hostname or ip address of the vault server.
	Port        string // The port of the vault server.
	Scheme      string // The scheme for vault URL. Should be either http or https.
	CACert      string // The path to the PEM-encoded CA cert file used to verify the Vault server SSL cert.
	ClientCert  string // The path to the client cert used for Vault communication.
	ClientKey   string // The paht to the client key used for Vault communication.
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

// MountCubbyhole mounts the provided path in Vault.
func MountCubbyhole(m Mounter) error {
	mci := vault.MountConfigInput{}
	mi := &vault.MountInput{
		Type:        "cubbyhole",
		Description: "A cubbyhole mount for iRODS configs",
		Config:      mci,
	}
	return m.Mount("cubbyhole/", mi)
}

// MountPKI mounts the provided path in Vault.
func MountPKI(m Mounter) error {
	mci := vault.MountConfigInput{}
	mi := &vault.MountInput{
		Type:        "pki",
		Description: "A pki backend for HTCondor jobs",
		Config:      mci,
	}
	return m.Mount("pki/", mi)
}

// PKIMountConfig returns the mount config for the PKI backend.
func PKIMountConfig(m MountConfigGetter) (*vault.MountConfigOutput, error) {
	return m.MountConfig("pki/")
}

// TunePKI tunes the mounted pki backend.
func TunePKI(t MountTuner, defaultTTL, maxTTL string) error {
	in := vault.MountConfigInput{
		DefaultLeaseTTL: defaultTTL,
		MaxLeaseTTL:     maxTTL,
	}
	return t.TuneMount("pki/", in)
}

func isBackendMounted(l MountLister, path string) (bool, error) {
	var (
		hasPath bool
		err     error
	)
	mounts, err := l.ListMounts()
	if err != nil {
		return false, err
	}
	for m := range mounts {
		if m == path {
			hasPath = true
		}
	}
	return hasPath, nil
}

// IsCubbyholeMounted returns true if the cubbyhole backend is mounted.
func IsCubbyholeMounted(l MountLister) (bool, error) {
	return isBackendMounted(l, "cubbyhole/")
}

// IsPKIMounted returns true if the pki backend is mounted.
func IsPKIMounted(l MountLister) (bool, error) {
	return isBackendMounted(l, "pki/")
}

// WriteToCubbyhole writes a string to a path in the cubbyhole backend. That
// path is tied to the token that is passed in.
func WriteToCubbyhole(cw CubbyholeWriter, token, content string) error {
	var (
		client *vault.Client
		err    error
	)
	if client, err = cw.NewClient(cw.GetConfig()); err != nil {
		return err
	}
	cw.SetToken(client, token)
	writePath := fmt.Sprintf("cubbyhole/%s", token)
	data := map[string]interface{}{
		"irods-config": content,
	}
	_, err = cw.Write(client, writePath, data)
	if err != nil {
		return err
	}
	return nil
}

// ReadFromCubbyhole reads and returns the secret from the path
// cubbyhole/<token> on the Vault server.
func ReadFromCubbyhole(cr CubbyholeReader, token string) (string, error) {
	var (
		client *vault.Client
		err    error
	)
	if client, err = cr.NewClient(cr.GetConfig()); err != nil {
		return "", err
	}
	cr.SetToken(client, token)
	readPath := fmt.Sprintf("cubbyhole/%s", token)
	secret, err := cr.Read(client, readPath)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", errors.New("secret is nil")
	}
	if secret.Data == nil {
		return "", errors.New("data is nil")
	}
	if _, ok := secret.Data["irods-config"]; !ok {
		return "", errors.New("data did not contain irods-config")
	}
	if secret.Data["irods-config"] == nil {
		return "", errors.New("irods-config is nil")
	}
	return secret.Data["irods-config"].(string), nil
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

// CreateRole creates a new role.
func CreateRole(r Roller, roleName, domains string, subdomains bool) (*vault.Secret, error) {
	client := r.Client()
	writePath := fmt.Sprintf("pki/roles/%s", roleName)
	data := map[string]interface{}{
		"allowed_domains":  domains,
		"allow_subdomains": strconv.FormatBool(subdomains),
	}
	return r.Write(client, writePath, data)
}

// HasRole returns true if the passed in role exists and has the same settings.
func HasRole(r Roller, roleName, domains string, subdomains bool) (bool, error) {
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
	fmt.Println(v)
	if v != strconv.FormatBool(subdomains) {
		return false, nil
	}
	return true, nil
}

// InitAPI initializes the provided *VaultAPI. This should be called first.
func InitAPI(api *VaultAPI, cfg *VaultAPIConfig, token string) error {
	var err error
	tlsconfig := &vault.TLSConfig{
		CACert:     cfg.CACert,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	}
	apicfg := api.DefaultConfig()
	apicfg.Address = fmt.Sprintf(
		"%s://%s:%s",
		cfg.Scheme,
		cfg.Host,
		cfg.Port,
	)
	if err = api.ConfigureTLS(apicfg, tlsconfig); err != nil {
		return err
	}
	var client *vault.Client
	if client, err = api.NewClient(apicfg); err != nil {
		return err
	}
	api.SetToken(client, token)
	api.SetClient(client)
	api.SetConfig(apicfg)
	return nil
}
