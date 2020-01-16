package main

import (
	"log"

	"github.com/streadway/amqp"
)

// BuildMqURI builds the MQ URI
func BuildMqURI(mqHost, mqPort, mqUser, mqPassword, mqVhost string, ssl bool) string {
	brokerURI := ""
	if ssl {
		brokerURI = "amqps://" + mqUser + ":" + mqPassword + "@" + mqHost + ":" + mqPort + mqVhost
	} else {
		brokerURI = "amqp://" + mqUser + ":" + mqPassword + "@" + mqHost + ":" + mqPort + mqVhost
	}
	return brokerURI
}

// One would typically keep a channel of publishings, a sequence number, and a
// set of unacknowledged sequence numbers and loop until the publishing channel
// is closed.
func confirmOne(confirms <-chan amqp.Confirmation) {
	log.Printf("waiting for confirmation of one publishing")

	if confirmed := <-confirms; confirmed.Ack {
		log.Printf("confirmed delivery with delivery tag: %d", confirmed.DeliveryTag)
	} else {
		log.Printf("failed delivery of delivery tag: %d", confirmed.DeliveryTag)
	}
}
