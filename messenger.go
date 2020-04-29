package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/streadway/amqp"
)

// Checksum used in the message
type Checksum struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// The Event struct
type Event struct {
	Operation string   `json:"operation"`
	Username  string   `json:"user"`
	Filepath  string   `json:"filepath"`
	Filesize  int64    `json:"filesize"`
	Checksum  Checksum `json:"encoded_checksum"`
}

// Messenger is an interface for sending messages for different file events
type Messenger interface {
	SendMessage(message Event) error
}

// AMQPMessenger is a Messenger that sends messages to a local AMQP broker
type AMQPMessenger struct {
	connection *amqp.Connection
	channel    *amqp.Channel
	exchange   string
	routingKey string
}

// NewAMQPMessenger creates a new messenger that can communicate with a backend
// amqp server.
func NewAMQPMessenger(c BrokerConfig, tlsConfig *tls.Config) *AMQPMessenger {
	brokerURI := buildMqURI(c.host, c.port, c.user, c.password, c.vhost, c.ssl)

	var connection *amqp.Connection
	var channel *amqp.Channel
	var err error

	log.Debugf("connecting to broker with <%s>", brokerURI)
	if c.ssl {
		connection, err = amqp.DialTLS(brokerURI, tlsConfig)
	} else {
		connection, err = amqp.Dial(brokerURI)
	}
	if err != nil {
		log.Panicf("brokerErrMsg 1: %s", err)
	}

	channel, err = connection.Channel()
	if err != nil {
		log.Panicf("brokerErrMsg 2: %s", err)
	}

	log.Debug("enabling publishing confirms.")
	if err = channel.Confirm(false); err != nil {
		log.Fatalf("channel could not be put into confirm mode: %s", err)
	}

	if err = channel.ExchangeDeclare(
		c.exchange, // name
		"topic",    // type
		true,       // durable
		false,      // auto-deleted
		false,      // internal
		false,      // noWait
		nil,        // arguments
	); err != nil {
		log.Fatalf("exchange declare: %s", err)
	}

	return &AMQPMessenger{connection, channel, c.exchange, c.routingKey}
}

// SendMessage sends message to RabbitMQ if the upload is finished
func (m *AMQPMessenger) SendMessage(message Event) error {
	// Set channel
	if e := m.channel.Confirm(false); e != nil {
		log.Fatalf("channel could not be put into confirm mode: %s", e)
	}

	// Shouldn't this be setup once and for all?
	confirms := m.channel.NotifyPublish(make(chan amqp.Confirmation, 100))
	defer confirmOne(confirms)

	body, e := json.Marshal(message)
	if e != nil {
		log.Fatalf("%s", e)
	}

	corrID, _ := uuid.NewRandom()

	err := m.channel.Publish(
		m.exchange,
		m.routingKey,
		false, // mandatory
		false, // immediate
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
	return err
}

// // One would typically keep a channel of publishings, a sequence number, and a
// // set of unacknowledged sequence numbers and loop until the publishing channel
// // is closed.
func confirmOne(confirms <-chan amqp.Confirmation) error {
	confirmed := <-confirms
	if !confirmed.Ack {
		return fmt.Errorf("failed delivery of delivery tag: %d", confirmed.DeliveryTag)
	}
	log.Printf("confirmed delivery with delivery tag: %d", confirmed.DeliveryTag)
	return nil
}

// BuildMqURI builds the MQ URI
func buildMqURI(mqHost, mqPort, mqUser, mqPassword, mqVhost string, ssl bool) string {
	brokerURI := ""
	if ssl {
		brokerURI = "amqps://" + mqUser + ":" + mqPassword + "@" + mqHost + ":" + mqPort + mqVhost
	} else {
		brokerURI = "amqp://" + mqUser + ":" + mqPassword + "@" + mqHost + ":" + mqPort + mqVhost
	}
	return brokerURI
}
