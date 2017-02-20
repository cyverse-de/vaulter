package main

import (
	"errors"
	"flag"
	"fmt"
	"log"

	vault "github.com/hashicorp/vault/api"
)

// AppConfig contains the applications configuration settings.
type AppConfig struct {
	ParentToken     string // Other tokens will be children of this token.
	VaultHost       string // The hostname or ip address of the vault server.
	VaultPort       string // The port of the vault server.
	VaultScheme     string // The scheme for vault URL. Should be either http or https.
	VaultCACert     string // The path to the PEM-encoded CA cert file used to verify the Vault server SSL cert.
	VaultClientCert string // The path to the client cert used for Vault communication.
	VaultClientKey  string // The paht to the client key used for Vault communication.
}

// App contains the overall state of the application.
type App struct {
	Client *vault.Client
}

// ChildToken creates a single-use child token of the provided parent token with
// a TTL of 32 days.
func (a *App) ChildToken() (clientToken string, err error) {
	opts := &vault.TokenCreateRequest{
		NumUses: 2,
	}
	ta := a.Client.Auth().Token()
	secret, err := ta.Create(opts)
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

// MountCubbyhole creates a new cubbyhole backend tied to the token passed in as
// a parameter. Creates a new client with NewVaultClient() rather than resetting
// the token on a.Client, which should prevent concurrency issues.
func (a *App) MountCubbyhole(c *AppConfig, token string) error {
	var (
		client *vault.Client
		err    error
	)
	if client, err = NewVaultClient(c, token); err != nil {
		return err
	}
	mci := vault.MountConfigInput{}
	mi := &vault.MountInput{
		Type:        "cubbyhole",
		Description: "A cubbyhole mount for iRODS configs",
		Config:      mci,
	}
	sys := client.Sys()
	return sys.Mount("/irods-configs", mi)
}

// IsCubbyholeMounted returns true if the cubbyhole backend is mounted. Which it
// should be already, but let's check just to be sure.
func (a *App) IsCubbyholeMounted() (bool, error) {
	var (
		hasPath       bool
		cubbyholePath = "cubbyhole/"
		err           error
	)
	sys := a.Client.Sys()
	mounts, err := sys.ListMounts()
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

// WriteToCubbyhole writes the provided string to a cubbyhole specific to the token
// provided.
func (a *App) WriteToCubbyhole(c *AppConfig, token, content string) error {
	var (
		client *vault.Client
		err    error
	)
	if client, err = NewVaultClient(c, token); err != nil {
		return err
	}
	logical := client.Logical()
	writePath := fmt.Sprintf("cubbyhole/%s", token)
	data := map[string]interface{}{
		"irods-config": content,
	}
	_, err = logical.Write(writePath, data)
	if err != nil {
		return err
	}
	return nil
}

// ReadFromCubbyhole reads a string from the cubbyhole path set up for the
// provided token.
func (a *App) ReadFromCubbyhole(c *AppConfig, token string) (string, error) {
	var (
		client *vault.Client
		err    error
	)
	if client, err = NewVaultClient(c, token); err != nil {
		return "", err
	}
	logical := client.Logical()
	readPath := fmt.Sprintf("cubbyhole/%s", token)
	secret, err := logical.Read(readPath)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", errors.New("secret is nil")
	}
	if secret.Data == nil {
		return "", errors.New("data is nil")
	}
	if secret.Data["irods-config"] == nil {
		return "", errors.New("irods-config is nil")
	}
	return secret.Data["irods-config"].(string), nil
}

// NewVaultClient returns a new *vault.Client instance configured to use the
// vault token passed in as a parameter. Can be used on initial setup with the
// root token and also with child tokens elsewhere in the code.
func NewVaultClient(c *AppConfig, token string) (*vault.Client, error) {
	var err error
	tlsconfig := &vault.TLSConfig{
		CACert:     c.VaultCACert,
		ClientCert: c.VaultClientCert,
		ClientKey:  c.VaultClientKey,
	}
	cfg := vault.DefaultConfig()
	cfg.Address = fmt.Sprintf("%s://%s:%s", c.VaultScheme, c.VaultHost, c.VaultPort)
	if err = cfg.ConfigureTLS(tlsconfig); err != nil {
		return nil, err
	}
	var client *vault.Client
	if client, err = vault.NewClient(cfg); err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, err
}

// NewApp returns a newly created *App.
func NewApp(c *AppConfig) (*App, error) {
	var (
		client *vault.Client
		err    error
	)
	if client, err = NewVaultClient(c, c.ParentToken); err != nil {
		return nil, err
	}
	return &App{
		Client: client,
	}, err
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
	)
	flag.Parse()

	ac := &AppConfig{
		ParentToken:     *parent,
		VaultHost:       *host,
		VaultPort:       *port,
		VaultScheme:     *scheme,
		VaultCACert:     *cacert,
		VaultClientCert: *clientcert,
		VaultClientKey:  *clientkey,
	}
	app, err := NewApp(ac)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%#v\n", app)
	sys := app.Client.Sys()
	mounts, err := sys.ListMounts()
	if err != nil {
		log.Fatal(err)
	}
	for k := range mounts {
		fmt.Println(k)
	}
	secret, err := app.ChildToken()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret)
	hasMount, err := app.IsCubbyholeMounted()
	if err != nil {
		log.Fatal(err)
	}
	if !hasMount {
		if err = app.MountCubbyhole(ac, ac.ParentToken); err != nil {
			log.Fatal(err)
		}
	}
	if err = app.WriteToCubbyhole(ac, secret, "foo"); err != nil {
		log.Fatal(err)
	}
	var read string
	if read, err = app.ReadFromCubbyhole(ac, secret); err != nil {
		log.Fatal(err)
	}
	log.Println(read)
}
