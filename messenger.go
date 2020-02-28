package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"regexp"
	//"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/streadway/amqp"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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

// CreateMessageFromRequest is a function that can take a http request and
// figure out the correct message to send from it.
func CreateMessageFromRequest(r *http.Request) (Event, error) {
	// Extract username for request's url path
	re := regexp.MustCompile("/([^/]+)/")
	username := re.FindStringSubmatch(r.URL.Path)[1]

	event := Event{}
	checksum := Checksum{}

	err := RequestInfo(r.URL.Path, &event, &checksum)
	if err != nil {
		log.Fatalf("Could not get checksum information: %s", err)
	}

	// Case for simple upload
	if r.Method == http.MethodPut {
		event.Operation = "upload"
		// Case for multi-part upload
	} else if r.Method == http.MethodPost {
		event.Operation = "multipart-upload"
	} else {
		return Event{}, fmt.Errorf("upload method has to be POST or PUT")
	}
	event.Filepath = r.URL.Path
	event.Username = username
	checksum.Type = "etag"
	event.Checksum = checksum

	return event, nil
}

func RequestInfo(fullPath string, event *Event, checksum *Checksum) error {
	filePath := strings.Replace(fullPath, "/"+viper.GetString("aws.bucket"), "", 1)

	// Used to disable certificate check
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	mySession, err := session.NewSession(&aws.Config{
		Region:           aws.String(viper.GetString("aws.region")),
		Endpoint:         aws.String(viper.GetString("aws.url")),
		DisableSSL:       aws.Bool(true),
		S3ForcePathStyle: aws.Bool(true),
		Credentials:      credentials.NewStaticCredentials(viper.GetString("aws.accessKey"), viper.GetString("aws.secretKey"), ""),
		// Used to disable certificate check
		HTTPClient: client,
	})
	if err != nil {
		return err
	}

	svc := s3.New(mySession)
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(viper.GetString("aws.bucket")),
		MaxKeys: aws.Int64(2),
		Prefix:  aws.String(filePath),
	}

	result, err := svc.ListObjectsV2(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				fmt.Println(s3.ErrCodeNoSuchBucket, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err)
		}
		return err
	}
	checksum.Value = strings.ReplaceAll(*result.Contents[0].ETag, "\"", "")
	event.Filesize = *result.Contents[0].Size
	return nil
}


// NewAMQPMessenger creates a new messenger that can communicate with a backend
// amqp server.
func NewAMQPMessenger(c BrokerConfig, tlsConfig *tls.Config) *AMQPMessenger {
	brokerURI := buildMqURI(c.host, c.port, c.user, c.password, c.vhost, c.ssl)

	var connection *amqp.Connection
	var channel *amqp.Channel
	var err error

	log.Printf("Connecting to broker with <%s>", brokerURI)
	if c.ssl {
		connection, err = amqp.DialTLS(brokerURI, tlsConfig)
	} else {
		connection, err = amqp.Dial(brokerURI)
	}
	if err != nil {
		panic(fmt.Errorf("BrokerErrMsg 1: %s", err))
	}

	channel, err = connection.Channel()
	if err != nil {
		panic(fmt.Errorf("BrokerErrMsg 2: %s", err))
	}

	log.Printf("enabling publishing confirms.")
	if err = channel.Confirm(false); err != nil {
		log.Fatalf("Channel could not be put into confirm mode: %s", err)
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
		log.Fatalf("Exchange Declare: %s", err)
	}

	return &AMQPMessenger{connection, channel, c.exchange, c.routingKey}
}

// SendMessage sends message to RabbitMQ if the upload is finished
// TODO: Use the actual username in both cases and size, checksum for multipart upload
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
