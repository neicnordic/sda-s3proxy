package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"reflect"
	"strings"

	"github.com/spf13/viper"
)

var (
	requiredConfVars = []string{
		"aws.url", "aws.accessKey", "aws.secretKey", "aws.bucket",
		"broker.host", "broker.port", "broker.user", "broker.password", "broker.vhost", "broker.exchange", "broker.routingKey",
	}
)

// S3Config stores information about the S3 backend
type S3Config struct {
	url       string
	readypath string
	accessKey string
	secretKey string
	bucket    string
	region    string
	cacert    string
}

// BrokerConfig stores information about the message broker
type BrokerConfig struct {
	host       string
	port       string
	user       string
	password   string
	vhost      string
	exchange   string
	routingKey string
	ssl        bool
	verifyPeer bool
	cacert     string
	clientCert string
	clientKey  string
	serverName string
}

// ServerConfig stores general server information
type ServerConfig struct {
	cert          string
	key           string
	users         string
	jwtpubkeypath string
	jwtpubkeyurl  string
}

// Config is a parent object for all the different configuration parts
type Config struct {
	S3     S3Config
	Broker BrokerConfig
	Server ServerConfig
}

// NewConfig initializes and parses the config file and/or environment using
// the viper library.
func NewConfig() *Config {
	parseConfig()

	c := &Config{}
	c.readConfig()

	return c
}

func (c *Config) readConfig() {
	s3 := S3Config{}

	// All these are required
	s3.url = viper.GetString("aws.url")
	s3.accessKey = viper.GetString("aws.accessKey")
	s3.secretKey = viper.GetString("aws.secretKey")
	s3.bucket = viper.GetString("aws.bucket")

	// Optional settings
	if viper.IsSet("aws.readypath") {
		s3.readypath = viper.GetString("aws.readypath")
	}
	if viper.IsSet("aws.region") {
		s3.region = viper.GetString("aws.region")
	} else {
		s3.region = "us-east-1"
	}
	if viper.IsSet("aws.cacert") {
		s3.cacert = viper.GetString("aws.cacert")
	}

	c.S3 = s3

	// Setup broker
	b := BrokerConfig{}

	b.host = viper.GetString("broker.host")
	b.port = viper.GetString("broker.port")
	b.user = viper.GetString("broker.user")
	b.password = viper.GetString("broker.password")
	b.vhost = viper.GetString("broker.vhost")
	b.exchange = viper.GetString("broker.exchange")
	b.routingKey = viper.GetString("broker.routingKey")
	b.serverName = viper.GetString("broker.serverName")

	if viper.IsSet("broker.ssl") {
		b.ssl = viper.GetBool("broker.ssl")
	}
	if viper.IsSet("broker.verifyPeer") {
		b.verifyPeer = viper.GetBool("broker.verifyPeer")
		// Since verifyPeer is specified, these are required.
		if !(viper.IsSet("broker.clientCert") && viper.IsSet("broker.clientKey")) {
			panic(fmt.Errorf("when broker.verifyPeer is set both broker.clientCert and broker.clientKey is needed"))
		}
		b.clientCert = viper.GetString("broker.clientCert")
		b.clientKey = viper.GetString("broker.clientKey")
	}
	if viper.IsSet("broker.cacert") {
		b.cacert = viper.GetString("broker.cacert")
	}

	c.Broker = b

	// Setup server
	s := ServerConfig{}

	if !(viper.IsSet("server.users") || viper.IsSet("server.jwtpubkeypath") || viper.IsSet("server.jwtpubkeyurl")) {
		panic(fmt.Errorf("either server.users or server.pubkey should be present to start the service"))
	}

	// User file authentication
	if viper.IsSet("server.users") {
		s.users = viper.GetString("server.users")
	}

	// Token authentication
	if viper.IsSet("server.jwtpubkeypath") {
		s.jwtpubkeypath = viper.GetString("server.jwtpubkeypath")
	}

	if viper.IsSet("server.jwtpubkeyurl") {
		s.jwtpubkeyurl = viper.GetString("server.jwtpubkeyurl")
	}

	if viper.IsSet("server.cert") {
		s.cert = viper.GetString("server.cert")
	}
	if viper.IsSet("server.key") {
		s.key = viper.GetString("server.key")
	}

	c.Server = s
}

func parseConfig() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetConfigType("yaml")
	if viper.IsSet("server.confPath") {
		cp := viper.GetString("server.confPath")
		ss := strings.Split(strings.TrimLeft(cp, "/"), "/")
		if ss[0] != "config" {
			ss = ss[:len(ss)-1]
		}
		viper.AddConfigPath(path.Join(ss...))
	}
	if viper.IsSet("server.confFile") {
		viper.SetConfigFile(viper.GetString("server.confFile"))
	}
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			for _, s := range requiredConfVars {
				if !viper.IsSet(s) {
					panic(fmt.Errorf("%s not set", s))
				}
			}
		} else {
			panic(fmt.Errorf("fatal error config file: %s", err))
		}
	}
}

// TLSConfigBroker is a helper method to setup TLS for the message broker
func TLSConfigBroker(c *Config) *tls.Config {
	cfg := new(tls.Config)

	log.Printf("Setting up TLS")

	// Enforce TLS1.2 or higher
	cfg.MinVersion = 2

	// Read system CAs
	var systemCAs, _ = x509.SystemCertPool()
	if reflect.DeepEqual(systemCAs, x509.NewCertPool()) {
		fmt.Println("creating new CApool")
		systemCAs = x509.NewCertPool()
	}
	cfg.RootCAs = systemCAs

	// Add CAs for broker and s3
	for _, cacert := range []string{c.Broker.cacert, c.S3.cacert} {
		if cacert == "" {
			continue
		}

		cacert, e := ioutil.ReadFile(cacert) // #nosec this file comes from our configuration
		if e != nil {
			log.Fatalf("Failed to append %q to RootCAs: %v", cacert, e)
		}
		if ok := cfg.RootCAs.AppendCertsFromPEM(cacert); !ok {
			log.Println("No certs appended, using system certs only")
		}
	}

	// This might be a bad thing to do globally, but we'll see.
	if c.Broker.serverName != "" {
		cfg.ServerName = c.Broker.serverName
	}

	if c.Broker.verifyPeer {
		if c.Broker.clientCert != "" && c.Broker.clientKey != "" {
			cert, e := ioutil.ReadFile(c.Broker.clientCert)
			if e != nil {
				log.Fatalf("Failed to append %q to RootCAs: %v", c.Broker.clientKey, e)
			}
			key, e := ioutil.ReadFile(c.Broker.clientKey)
			if e != nil {
				log.Fatalf("Failed to append %q to RootCAs: %v", c.Broker.clientKey, e)
			}
			if certs, e := tls.X509KeyPair(cert, key); e == nil {
				cfg.Certificates = append(cfg.Certificates, certs)
			}
		} else {
			fmt.Println("No certs")
			log.Fatalf("brokerErrMsg: No certs")
		}
	}
	return cfg
}

// TLSConfigProxy is a helper method to setup TLS for the S3 backend.
func TLSConfigProxy(c *Config) *tls.Config {
	cfg := new(tls.Config)

	log.Printf("Setting up TLS")

	// Enforce TLS1.2 or higher
	cfg.MinVersion = 2

	// Read system CAs
	var systemCAs, _ = x509.SystemCertPool()
	if reflect.DeepEqual(systemCAs, x509.NewCertPool()) {
		fmt.Println("creating new CApool")
		systemCAs = x509.NewCertPool()
	}
	cfg.RootCAs = systemCAs

	if c.S3.cacert != "" {
		cacert, e := ioutil.ReadFile(c.S3.cacert) // #nosec this file comes from our configuration
		if e != nil {
			log.Fatalf("Failed to append %q to RootCAs: %v", cacert, e)
		}
		if ok := cfg.RootCAs.AppendCertsFromPEM(cacert); !ok {
			log.Println("No certs appended, using system certs only")
		}
	}

	return cfg
}
