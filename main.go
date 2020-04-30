package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

func main() {
	config := NewConfig()

	tlsBroker := TLSConfigBroker(config)
	tlsProxy := TLSConfigProxy(config)
	messenger := NewAMQPMessenger(config.Broker, tlsBroker)
	log.Debug("messenger acquired ", messenger)

	var pubkeys map[string][]byte
	auth := NewValidateFromToken(pubkeys)
	auth.pubkeys = make(map[string][]byte)
	// Load keys for JWT verification
	if config.Server.jwtpubkeyurl != "" {
		if err := auth.getjwtpubkey(config.Server.jwtpubkeyurl); err != nil {
			log.Panic("either server.users or server.jwtpubkeyurl should be present to start the service")
		}
	}
	if config.Server.jwtpubkeypath != "" {
		if err := auth.getjwtkey(config.Server.jwtpubkeypath); err != nil {
			log.Panic("either server.users or server.jwtpubkeypath should be present to start the service")
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
