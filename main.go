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

// Vaulter defines interactions with a Vault server. Mostly useful for stubbing
// stuff out for unit tests.
type Vaulter interface {
	ChildToken() (*vault.Secret, error)
	NewClient(token string) (*vault.Client, error)
	MountCubbyhole() error
	IsCubbyholeMounted() (bool, error)
	WriteToCubbyhole(token, content string) error
	ReadFromCubbyhole(token string) (*vault.Secret, error)
}

// AppVaulter is a Vaulter that actually interacts with a Vault server.
type AppVaulter struct {
	client *vault.Client
	cfg    *AppConfig
}

// ChildToken generates a new token that's a child of the one configured for the
// *AppVaulter vault client.
func (v *AppVaulter) ChildToken() (string, error) {
	opts := &vault.TokenCreateRequest{
		NumUses: 2,
	}
	ta := v.client.Auth().Token()
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

// MountCubbyhole mounts the provided path in Vault.
func (v *AppVaulter) MountCubbyhole() error {
	mci := vault.MountConfigInput{}
	mi := &vault.MountInput{
		Type:        "cubbyhole",
		Description: "A cubbyhole mount for iRODS configs",
		Config:      mci,
	}
	sys := v.client.Sys()
	return sys.Mount("cubbyhole/", mi)
}

// IsCubbyholeMounted returns true if the cubbyhole backend is mounted.
func (v *AppVaulter) IsCubbyholeMounted() (bool, error) {
	var (
		hasPath       bool
		cubbyholePath = "cubbyhole/"
		err           error
	)
	sys := v.client.Sys()
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

// NewClient returns a new *vault.Client instance configured to use the
// vault token passed in as a parameter. Can be used on initial setup with the
// root token and also with child tokens elsewhere in the code.
func (v *AppVaulter) NewClient(token string) (*vault.Client, error) {
	var err error
	tlsconfig := &vault.TLSConfig{
		CACert:     v.cfg.VaultCACert,
		ClientCert: v.cfg.VaultClientCert,
		ClientKey:  v.cfg.VaultClientKey,
	}
	cfg := vault.DefaultConfig()
	cfg.Address = fmt.Sprintf(
		"%s://%s:%s",
		v.cfg.VaultScheme,
		v.cfg.VaultHost,
		v.cfg.VaultPort,
	)
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

// WriteToCubbyhole writes a string to a path in the cubbyhole backend. That
// path is tied to the token that is passed in.
func (v *AppVaulter) WriteToCubbyhole(token, content string) error {
	var (
		client *vault.Client
		err    error
	)
	if client, err = v.NewClient(token); err != nil {
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

// ReadFromCubbyhole reads and returns the secret from the path
// cubbyhole/<token> on the Vault server.
func (v *AppVaulter) ReadFromCubbyhole(token string) (string, error) {
	var (
		client *vault.Client
		err    error
	)
	if client, err = v.NewClient(token); err != nil {
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

	ac := &AppConfig{
		ParentToken:     *parent,
		VaultHost:       *host,
		VaultPort:       *port,
		VaultScheme:     *scheme,
		VaultCACert:     *cacert,
		VaultClientCert: *clientcert,
		VaultClientKey:  *clientkey,
	}
	av := &AppVaulter{
		cfg: ac,
	}
	av.client, err = av.NewClient(av.cfg.ParentToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%#v\n", av)
	sys := av.client.Sys()
	mounts, err := sys.ListMounts()
	if err != nil {
		log.Fatal(err)
	}
	for k := range mounts {
		fmt.Println(k)
	}
	secret, err := av.ChildToken()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret)
	hasMount, err := av.IsCubbyholeMounted()
	if err != nil {
		log.Fatal(err)
	}
	if !hasMount {
		if err = av.MountCubbyhole(); err != nil {
			log.Fatal(err)
		}
	}
	if err = av.WriteToCubbyhole(secret, "foo"); err != nil {
		log.Fatal(err)
	}
	var read string
	if read, err = av.ReadFromCubbyhole(secret); err != nil {
		log.Fatal(err)
	}
	log.Println(read)
}
