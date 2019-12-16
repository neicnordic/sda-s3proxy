package mq

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/streadway/amqp"
)

func BuildMqUri(mqHost, mqPort, mqUser, mqPassword, mqVhost, ssl string) string {
	brokerUri := ""
	if ssl == "true" {
		brokerUri = "amqps://" + mqUser + ":" + mqPassword + "@" + mqHost + ":" + mqPort + mqVhost
	} else {
		brokerUri = "amqp://" + mqUser + ":" + mqPassword + "@" + mqHost + ":" + mqPort + mqVhost
	}
	return brokerUri
}

func DialTLS(amqpURI string, cfg *tls.Config) (*amqp.Connection, error) {
	connection, err := amqp.DialTLS(amqpURI, cfg)
	if err != nil {
		return nil, fmt.Errorf("Dial: %s", err)
	}
	log.Printf("conn: %v, err: %v", connection, err)

	return connection, nil
}

func Dial(amqpURI string) (*amqp.Connection, error) {
	connection, err := amqp.Dial(amqpURI)
	if err != nil {
		return nil, fmt.Errorf("Dial: %s", err)
	}

	return connection, nil
}

func Channel(connection *amqp.Connection) (*amqp.Channel, error) {
	log.Printf("got Connection, getting Channel")
	channel, err := connection.Channel()
	if err != nil {
		return nil, fmt.Errorf("Channel: %s", err)
	}

	return channel, nil
}

func Exchange(channel *amqp.Channel, exchange string) error {
	log.Printf("got Channel, declaring topic Exchange (%q)", exchange)
	if err := channel.ExchangeDeclare(
		exchange, // name
		"topic",  // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // noWait
		nil,      // arguments
	); err != nil {
		return fmt.Errorf("Exchange Declare: %s", err)
	}

	return nil
}

func Publish(exchange, routingKey, body string, reliable bool, channel *amqp.Channel) error {

	// Reliable publisher confirms require confirm.select support from the
	// connection.
	if reliable {
		log.Printf("enabling publishing confirms.")
		if err := channel.Confirm(false); err != nil {
			return fmt.Errorf("Channel could not be put into confirm mode: %s", err)
		}

		confirms := channel.NotifyPublish(make(chan amqp.Confirmation, 1))

		defer confirmOne(confirms)
	}

	corrID, _ := uuid.NewRandom()
	log.Printf("declared Exchange, publishing %dB body (%q)", len(body), body)
	err := channel.Publish(
		exchange,   // publish to an exchange
		routingKey, // routing to 0 or more queues
		false,      // mandatory
		false,      // immediate
		amqp.Publishing{
			Headers:         amqp.Table{},
			ContentEncoding: "UTF-8",
			ContentType:     "application/json",
			DeliveryMode:    amqp.Transient, // 1=non-persistent, 2=persistent
			CorrelationId:   corrID.String(),
			Priority:        0, // 0-9
			Body:            []byte(body),
			// a bunch of application/implementation-specific fields
		},
	)
	if err != nil {
		return fmt.Errorf("Exchange Publish: %s", err)
	}

	return nil
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
