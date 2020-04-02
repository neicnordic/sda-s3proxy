package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	config := NewConfig()

	tlsBroker := TLSConfigBroker(config)
	tlsProxy := TLSConfigProxy(config)
	messenger := NewAMQPMessenger(config.Broker, tlsBroker)
	log.Print("Messenger acquired ", messenger)

	var pubkeys map[string][]byte
	auth := NewValidateFromToken(pubkeys)
	auth.pubkeys = make(map[string][]byte)
	// Load keys for JWT verification
	if config.Server.jwtpubkeyurl != "" {
		err := auth.getjwtpubkey(config.Server.jwtpubkeyurl)
		if err != nil {
			panic(fmt.Errorf("either server.users or server.pubkey should be present to start the service"))
		}
	}
	if config.Server.jwtpubkeypath != "" {
		err := auth.getjwtKey(config.Server.jwtpubkeypath)
		if err != nil {
			panic(fmt.Errorf("either server.users or server.pubkey should be present to start the service"))
		}
	}
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
