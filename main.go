package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
)

func main() {
	config := NewConfig()

	tlsBroker := TLSConfigBroker(config)
	tlsProxy := TLSConfigProxy(config)
	messenger := NewAMQPMessenger(config.Broker, tlsBroker)
	log.Print("Messenger acquired ", messenger)

	auth := NewValidateFromFile(config.Server.users)
	proxy := NewProxy(config.S3, auth, messenger, tlsProxy)
	log.Print("Got the Proxy ", proxy)

	http.Handle("/", proxy)

	hc := NewHealthCheck(8001, config.S3, config.Broker, tlsProxy)
	go hc.RunHealthChecks()

	if config.Server.cert != "" && config.Server.key != "" {
		if e := http.ListenAndServeTLS(":8000", config.Server.cert, config.Server.key, nil); e != nil {
			panic(e)
		}
	} else {
		if e := http.ListenAndServe(":8000", nil); e != nil {
			panic(e)
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
