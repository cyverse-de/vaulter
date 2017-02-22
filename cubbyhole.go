package cubbyhole

import (
	"errors"
	"flag"
	"fmt"
	"log"

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
	Write(c *vault.Client, path string, data map[string]interface{}) error
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

// Vaulter defines the lower-level interactions with vault so that they can be
// stubbed out in unit tests.
type Vaulter interface {
	Tokener
	Mounter
	MountLister
	Configurer
	ConfigGetter
	ConfigSetter
	ClientCreator
	ClientSetter
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

func (v *VaultAPI) Write(client *vault.Client, path string, data map[string]interface{}) error {
	logical := client.Logical()
	_, err := logical.Write(path, data)
	return err
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

// IsCubbyholeMounted returns true if the cubbyhole backend is mounted.
func IsCubbyholeMounted(l MountLister) (bool, error) {
	var (
		hasPath       bool
		cubbyholePath = "cubbyhole/"
		err           error
	)
	mounts, err := l.ListMounts()
	if err != nil {
		return false, err
	}
	for m := range mounts {
		if m == cubbyholePath {
			hasPath = true
		}
	}
	return hasPath, nil
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
	err = cw.Write(client, writePath, data)
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
	// Note that we're calling the Cubbyhole version of NewClient(), not the
	// VaultAPI version.
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

func main() {
	var (
		parent     = flag.String("token", "", "The parent Vault token.")
		host       = flag.String("host", "", "The Vault host to connect to.")
		port       = flag.String("port", "8200", "The Vault port to connect to.")
		scheme     = flag.String("scheme", "https", "The protocol scheme to use when connecting to Vault.")
		cacert     = flag.String("ca-cert", "", "The path to the CA cert for Vault SSL cert validation.")
		clientcert = flag.String("client-cert", "", "The path to the client cert for Vault connections.")
		clientkey  = flag.String("client-key", "", "The path to the client key for Vault connections.")
		err        error
	)
	flag.Parse()

	cc := &VaultAPIConfig{
		ParentToken: *parent,
		Host:        *host,
		Port:        *port,
		Scheme:      *scheme,
		CACert:      *cacert,
		ClientCert:  *clientcert,
		ClientKey:   *clientkey,
	}
	vaultAPI := &VaultAPI{}
	if err = InitAPI(vaultAPI, cc, cc.ParentToken); err != nil {
		log.Fatal(err)
	}
	mounts, err := vaultAPI.ListMounts()
	if err != nil {
		log.Fatal(err)
	}
	for k := range mounts {
		fmt.Println(k)
	}
	secret, err := ChildToken(vaultAPI)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret)
	hasMount, err := IsCubbyholeMounted(vaultAPI)
	if err != nil {
		log.Fatal(err)
	}
	if !hasMount {
		if err = MountCubbyhole(vaultAPI); err != nil {
			log.Fatal(err)
		}
	}
	if err = WriteToCubbyhole(vaultAPI, secret, "foo"); err != nil {
		log.Fatal(err)
	}
	var read string
	if read, err = ReadFromCubbyhole(vaultAPI, secret); err != nil {
		log.Fatal(err)
	}
	log.Println(read)

	if _, err = ReadFromCubbyhole(vaultAPI, secret); err == nil {
		log.Fatal(errors.New("err was nil"))
	} else {
		fmt.Printf("correctly received the following error: %s\n", err)
	}
}
