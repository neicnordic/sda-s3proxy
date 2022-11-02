package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

func main() {
	// Create a function to handle panic and exit gracefully
	defer func() {
		if err := recover(); err != nil {
			log.Fatal("Could not recover, exiting")
		}
	}()

	config, err := NewConfig()
	if err != nil {
		log.Panic(err)
	}
	tlsBroker, err := TLSConfigBroker(config)
	if err != nil {
		log.Panic(err)
	}
	tlsProxy, err := TLSConfigProxy(config)
	if err != nil {
		log.Panic(err)
	}

	err = checkS3Bucket(config.S3)
	if err != nil {
		log.Panic(err)
	}

	messenger := NewAMQPMessenger(config.Broker, tlsBroker)
	log.Debug("messenger acquired ", messenger)

	var pubkeys map[string][]byte
	auth := NewValidateFromToken(pubkeys)
	auth.pubkeys = make(map[string][]byte)
	// Load keys for JWT verification
	if config.Server.jwtpubkeyurl != "" {
		if err := auth.getjwtpubkey(config.Server.jwtpubkeyurl); err != nil {
			log.Panicf("Error while getting key %s: %v", config.Server.jwtpubkeyurl, err)
		}
	}
	if config.Server.jwtpubkeypath != "" {
		if err := auth.getjwtkey(config.Server.jwtpubkeypath); err != nil {
			log.Panicf("Error while getting key %s: %v", config.Server.jwtpubkeypath, err)
		}
	}
	proxy := NewProxy(config.S3, auth, messenger, tlsProxy)

	log.Debug("got the proxy ", proxy)

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
