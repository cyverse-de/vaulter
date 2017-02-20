package main

import (
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

// NewApp returns a newly created *App.
func NewApp(c *AppConfig) (*App, error) {
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
	app.Client.SetToken(*parent)
	fmt.Printf("%#v\n", app)
	sys := app.Client.Sys()
	mounts, err := sys.ListMounts()
	if err != nil {
		log.Fatal(err)
	}
	for k := range mounts {
		fmt.Println(k)
	}
}
