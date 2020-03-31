package main

import (
	"log"
	"net/http"
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
