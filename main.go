package main

import (
	"net/http"
	"time"

	common "github.com/neicnordic/sda-common/database"
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

	sdaDB, err := common.NewSDAdb(config.DB)
	if err != nil {
		log.Fatal(err)
	}

	defer sdaDB.Close()

	log.Infof("Connected to sda-db (v%v)", sdaDB.Version)

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
	proxy := NewProxy(config.S3, auth, messenger, sdaDB, tlsProxy)

	log.Debug("got the proxy ", proxy)

	http.Handle("/", proxy)

	hc := NewHealthCheck(8001, config.S3, config.Broker, tlsProxy)
	go hc.RunHealthChecks()

	server := &http.Server{
		Addr:              ":8000",
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
	}

	if config.Server.cert != "" && config.Server.key != "" {
		if err := server.ListenAndServeTLS(config.Server.cert, config.Server.key); err != nil {
			panic(err)
		}
	} else {
		if err := server.ListenAndServe(); err != nil {
			panic(err)
		}
	}
}
