package main

import (
	"net/http"
	"time"

	common "github.com/neicnordic/sda-common/database"
	log "github.com/sirupsen/logrus"
)

// Export Conf so we can access it in the other modules
var Conf *Config

func main() {
	// Create a function to handle panic and exit gracefully
	defer func() {
		if err := recover(); err != nil {
			log.Fatal("Could not recover, exiting")
		}
	}()

	c, err := NewConfig()
	if err != nil {
		log.Panic(err)
	}
	Conf = c

	tlsBroker, err := TLSConfigBroker(Conf)
	if err != nil {
		log.Panic(err)
	}
	tlsProxy, err := TLSConfigProxy(Conf)
	if err != nil {
		log.Panic(err)
	}

	sdaDB, err := common.NewSDAdb(Conf.DB)
	if err != nil {
		log.Panic(err)
	}

	defer sdaDB.Close()

	log.Debugf("Connected to sda-db (v%v)", sdaDB.Version)

	err = checkS3Bucket(Conf.S3)
	if err != nil {
		log.Panic(err)
	}

	messenger := NewAMQPMessenger(Conf.Broker, tlsBroker)
	log.Debug("messenger acquired ", messenger)

	var pubkeys map[string][]byte
	auth := NewValidateFromToken(pubkeys)
	auth.pubkeys = make(map[string][]byte)
	// Load keys for JWT verification
	if Conf.Server.jwtpubkeyurl != "" {
		if err := auth.getjwtpubkey(Conf.Server.jwtpubkeyurl); err != nil {
			log.Panicf("Error while getting key %s: %v", Conf.Server.jwtpubkeyurl, err)
		}
	}
	if Conf.Server.jwtpubkeypath != "" {
		if err := auth.getjwtkey(Conf.Server.jwtpubkeypath); err != nil {
			log.Panicf("Error while getting key %s: %v", Conf.Server.jwtpubkeypath, err)
		}
	}
	proxy := NewProxy(Conf.S3, auth, messenger, sdaDB, tlsProxy)

	log.Debug("got the proxy ", proxy)

	http.Handle("/", proxy)

	hc := NewHealthCheck(8001, Conf.S3, Conf.Broker, tlsProxy)
	go hc.RunHealthChecks()

	server := &http.Server{
		Addr:              ":8000",
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
	}

	if Conf.Server.cert != "" && Conf.Server.key != "" {
		if err := server.ListenAndServeTLS(Conf.Server.cert, Conf.Server.key); err != nil {
			panic(err)
		}
	} else {
		if err := server.ListenAndServe(); err != nil {
			panic(err)
		}
	}
}
