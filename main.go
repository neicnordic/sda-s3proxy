package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v6/pkg/s3signer"
	"github.com/spf13/viper"
	"github.com/streadway/amqp"
)

var (
	confVars = []string{
		"aws.url", "aws.accessKey", "aws.secretKey", "aws.bucket", "broker.host", "broker.port", "broker.user",
		"broker.password", "broker.vhost", "broker.exchange", "broker.routingKey", "server.users",
	}
	err error
)

var logHandle *os.File

// AmqpChannel is an AmqpChannel
var AmqpChannel *amqp.Channel

// SystemCAs holds the Ca certs from the base system
var SystemCAs, _ = x509.SystemCertPool()

// S3RequestType is the
type S3RequestType int

// This is a list of constants for detecting S3 actions
const (
	MakeBucket S3RequestType = iota
	RemoveBucket
	List
	Put
	Get
	Delete
	AbortMultipart
	Policy
	Other
)

func main() {
	initialization()
	connection := brokerConnection()
	AmqpChannel, err = connection.Channel()
	if err != nil {
		panic(fmt.Errorf("BrokerErrMsg: %s", err))
	}

	log.Printf("enabling publishing confirms.")
	if err = AmqpChannel.Confirm(false); err != nil {
		log.Fatalf("Channel could not be put into confirm mode: %s", err)
	}

	if err = AmqpChannel.ExchangeDeclare(
		viper.GetString("broker.exchange"), // name
		"topic",                            // type
		true,                               // durable
		false,                              // auto-deleted
		false,                              // internal
		false,                              // noWait
		nil,                                // arguments
	); err != nil {
		log.Fatalf("Exchange Declare: %s", err)
	}

	logHandle, _ = os.Create("_requestLog.dump")

	http.HandleFunc("/", handler)

	go healthchecks(8001)

	if viper.IsSet("server.Cert") && viper.IsSet("server.Key") {
		if e := http.ListenAndServeTLS(":8000", viper.GetString("server.Cert"), viper.GetString("server.Key"), nil); e != nil {
			panic(e)
		}
	} else {
		if e := http.ListenAndServe(":8000", nil); e != nil {
			panic(e)
		}
	}

	defer AmqpChannel.Close()
	defer connection.Close()

}

// Initializes variables
func initialization() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetConfigType("yaml")
	if viper.IsSet("server.confPath") {
		cp := viper.GetString("server.confPath")
		ss := strings.Split(strings.TrimLeft(cp, "/"), "/")
		if ss[0] != "config" {
			ss = ss[:len(ss)-1]
		}
		viper.AddConfigPath(path.Join(ss...))
	}
	if viper.IsSet("server.confFile") {
		viper.SetConfigFile(viper.GetString("server.confFile"))
	}
	if err = viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			for _, s := range confVars {
				if !viper.IsSet(s) {
					panic(fmt.Errorf("%s not set", s))
				}
			}

		} else {
			panic(fmt.Errorf("fatal error config file: %s", err))
		}
	}

	if reflect.DeepEqual(SystemCAs, x509.NewCertPool()) {
		fmt.Println("creating new CApool")
		SystemCAs = x509.NewCertPool()
	}
}

// Creates the connection to the broker
func brokerConnection() *amqp.Connection {

	brokerURI := buildMqURI(viper.GetString("broker.host"), viper.GetString("broker.port"), viper.GetString("broker.user"), viper.GetString("broker.password"), viper.GetString("broker.vhost"), viper.GetBool("broker.ssl"))

	if viper.GetBool("broker.ssl") {
		cfg := new(tls.Config)

		// Enforce TLS1.2 or higher
		cfg.MinVersion = 2

		cfg.RootCAs = SystemCAs

		if viper.IsSet("broker.serverName") {
			cfg.ServerName = viper.GetString("broker.serverName")
		}

		if viper.IsSet("broker.caCert") {
			cacert, e := ioutil.ReadFile(viper.GetString("broker.caCert"))
			if e != nil {
				log.Fatalf("Failed to append %q to RootCAs: %v", cacert, e)
			}
			if ok := cfg.RootCAs.AppendCertsFromPEM(cacert); !ok {
				log.Println("No certs appended, using system certs only")
			}
		}

		if viper.IsSet("broker.verifyPeer") && viper.GetBool("broker.verifyPeer") {
			if viper.IsSet("broker.clientCert") && viper.IsSet("broker.clientKey") {
				cert, e := ioutil.ReadFile(viper.GetString("broker.clientCert"))
				if e != nil {
					log.Fatalf("Failed to append %q to RootCAs: %v", cert, e)
				}
				key, e := ioutil.ReadFile(viper.GetString("broker.clientKey"))
				if e != nil {
					log.Fatalf("Failed to append %q to RootCAs: %v", key, e)
				}
				if certs, e := tls.X509KeyPair(cert, key); e == nil {
					cfg.Certificates = append(cfg.Certificates, certs)
				}
			} else {
				fmt.Println("No certs")
				log.Fatalf("brokerErrMsg: No certs")
			}
		}

		connection, err := amqp.DialTLS(brokerURI, cfg)
		if err != nil {
			panic(fmt.Errorf("BrokerErrMsg: %s", err))
		} else {
			return connection
		}
	} else {
		connection, err := amqp.Dial(brokerURI)
		if err != nil {
			panic(fmt.Errorf("BrokerErrMsg: %s", err))
		} else {
			return connection
		}
	}

}

//Function for reading users mock file into a dictionary
func readUsersFile() map[string]string {
	users := make(map[string]string)
	f, e := os.Open(viper.GetString("server.users"))
	if e != nil {
		panic(fmt.Errorf("UsersFileErrMsg: %s", e))
	}

	r := csv.NewReader(bufio.NewReader(f))
	for {
		record, e := r.Read()
		if e == io.EOF {
			break
		}
		users[record[0]] = record[1]
	}
	return users
}

// Function for signing the headers of the s3 requests
// Used for for creating a signature for with the default
// credentials of the s3 service and the user's signature (authentication)
func resignHeader(r *http.Request, accessKey string, secretKey string, backendURL string) *http.Request {
	if strings.Contains(backendURL, "//") {
		host := strings.SplitN(backendURL, "//", 2)
		r.Host = host[1]
	}
	backendRegion := "us-east-1"
	if viper.IsSet("aws.region") {
		backendRegion = viper.GetString("aws.region")
	}
	return s3signer.SignV4(*r, accessKey, secretKey, "", backendRegion)
}

// Identifies the type of request based on the method and the url path
func detectRequestType(r *http.Request) S3RequestType {
	switch r.Method {
	case http.MethodGet:
		if strings.HasSuffix(r.URL.String(), "/") {
			return Get
		} else if strings.Contains(r.URL.String(), "?acl") {
			return Policy
		} else {
			return List
		}
	case http.MethodDelete:
		if strings.HasSuffix(r.URL.String(), "/") {
			return RemoveBucket
		} else if strings.Contains(r.URL.String(), "uploadId") {
			return AbortMultipart
		} else {
			// Do we allow deletion of files?
			return Delete
		}
	case http.MethodPut:
		if strings.HasSuffix(r.URL.String(), "/") {
			return MakeBucket
		} else if strings.Contains(r.URL.String(), "?policy") {
			return Policy
		} else {
			// Should decide if we will handle copy here or through authentication
			return Put
		}
	}
	return Other
}

// Authenticates the user against stored credentials
// 1) Extracts the username and retrieve the key from the map
// 2) Sign the request with the new credentials
// 3) Compare the signatures between the requests and return authentication status
func authenticateUser(r *http.Request) error {
	re := regexp.MustCompile("Credential=([^/]+)/")
	curAccessKey := ""
	if tmp := re.FindStringSubmatch(r.Header.Get("Authorization")); tmp != nil {
		// Check if user requested own bucket
		curAccessKey = tmp[1]
		re := regexp.MustCompile("/([^/]+)/")
		if curAccessKey != re.FindStringSubmatch(r.URL.Path)[1] {
			return fmt.Errorf("user not authorized to access location")
		}
	} else {
		log.Println("User not found in signature")
		return fmt.Errorf("user not found in signature")
	}
	usersMap := readUsersFile()
	if curSecretKey, ok := usersMap[curAccessKey]; ok {
		if r.Method == http.MethodGet {
			re := regexp.MustCompile("Signature=(.*)")

			signature := re.FindStringSubmatch(r.Header.Get("Authorization"))
			if signature == nil {
				return fmt.Errorf("user signature not found")
			}

			// Create signing request
			nr, e := http.NewRequest(r.Method, r.URL.String(), r.Body)
			if e != nil {
				fmt.Println(e)
			}

			// Add required headers
			nr.Header.Set("X-Amz-Date", r.Header.Get("X-Amz-Date"))
			nr.Header.Set("X-Amz-Content-Sha256", r.Header.Get("X-Amz-Content-Sha256"))
			nr.Host = r.Host
			nr.URL.RawQuery = r.URL.RawQuery

			// Sign the new request
			resignHeader(nr, curAccessKey, curSecretKey, nr.Host)
			curSignature := re.FindStringSubmatch(nr.Header.Get("Authorization"))

			// Compare signatures
			if curSignature[1] != signature[1] {
				return fmt.Errorf("user signature not authenticated")
			}
		}
	} else {
		log.Println("User not existing: ", curAccessKey)
		return fmt.Errorf("user not existing")
	}
	return nil
}

func notAuthorized(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(401) // Actually correct!
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Log request
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Fprintln(logHandle, "FORWARDING REQUEST TO BACKEND")
	fmt.Fprintln(logHandle, string(dump))

	switch t := detectRequestType(r); t {
	case MakeBucket, RemoveBucket, Delete, Policy, Get:
		// Not allowed
		notAllowedResponse(w, r)
	case Put, List, Other, AbortMultipart:
		// Allowed
		allowedResponse(w, r)
	default:
		fmt.Printf("Don't know how to handle %q\n", t)
		notAllowedResponse(w, r)
	}
}

func notAllowedResponse(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(403)
}

func allowedResponse(w http.ResponseWriter, r *http.Request) {

	if err := authenticateUser(r); err != nil {
		fmt.Println(err)
		notAuthorized(w, r)
		return
	}

	// Extract username for request's url path
	bucket := viper.GetString("aws.bucket")
	re := regexp.MustCompile("/([^/]+)/")
	username := re.FindStringSubmatch(r.URL.Path)[1]

	// Restructure request to query the users folder instead of the general bucket
	if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "?delimiter") {
		r.URL.Path = "/" + bucket + "/"
		if strings.Contains(r.URL.RawQuery, "&prefix") {
			params := strings.Split(r.URL.RawQuery, "&prefix=")
			r.URL.RawQuery = params[0] + "&prefix=" + username + "%2F" + params[1]
		} else {
			r.URL.RawQuery = r.URL.RawQuery + "&prefix=" + username + "%2F"
		}
	} else if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "?location") {
		r.URL.Path = "/" + bucket + "/"
	} else if r.Method == http.MethodPost || r.Method == http.MethodPut {
		r.URL.Path = "/" + bucket + r.URL.Path
	}
	resignHeader(r, viper.GetString("aws.accessKey"), viper.GetString("aws.secretKey"), viper.GetString("aws.url"))

	cfg := new(tls.Config)

	cfg.RootCAs = SystemCAs

	if viper.IsSet("aws.cacert") {
		cacert, err := ioutil.ReadFile(viper.GetString("aws.cacert"))
		if err != nil {
			log.Fatalf("Failed to append %q to RootCAs: %v", cacert, err)
		}

		if ok := cfg.RootCAs.AppendCertsFromPEM(cacert); !ok {
			log.Println("No certs appended, using system certs only")
		}
	}

	tr := &http.Transport{TLSClientConfig: cfg}
	client := &http.Client{Transport: tr}

	// Redirect request
	nr, err := http.NewRequest(r.Method, viper.GetString("aws.url")+r.URL.String(), r.Body)
	if err != nil {
		fmt.Println(err)
	}
	nr.Header = r.Header
	contentLength, _ := strconv.ParseInt(r.Header.Get("content-length"), 10, 64)
	nr.ContentLength = contentLength
	response, err := client.Do(nr)
	if err != nil {
		fmt.Println(err)
	}

	// Log answer
	responseDump, err := httputil.DumpResponse(response, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Fprintln(logHandle, "FORWARDING RESPONSE TO CLIENT")
	fmt.Fprintln(logHandle, string(responseDump))

	for header, values := range response.Header {
		for _, value := range values {
			w.Header().Add(header, value)
		}
	}

	if (nr.Method == http.MethodPut && response.StatusCode == 200 && !strings.Contains(nr.URL.String(), "partNumber")) ||
		(nr.Method == http.MethodPost && response.StatusCode == 200 && strings.Contains(nr.URL.String(), "uploadId")) {
		if e := AmqpChannel.Confirm(false); e != nil {
			log.Fatalf("channel could not be put into confirm mode: %s", e)
		}

		confirms := AmqpChannel.NotifyPublish(make(chan amqp.Confirmation, 100))
		defer confirmOne(confirms)
		if err = sendMessage(nr, r, response, contentLength, username); err != nil {
			log.Printf("error when sending message: %v", err)
		}
	}
	// Redirect answer
	_, err = io.Copy(w, response.Body)
	if err != nil {
		log.Fatalln("redirect error")
	}
}

// Sends message to RabbitMQ if the upload is finished
// TODO: Use the actual username in both cases and size, checksum for multipart upload
func sendMessage(nr *http.Request, r *http.Request, response *http.Response, contentLength int64, username string) error {
	event := Event{}
	checksum := Checksum{}

	// Case for simple upload
	if nr.Method == http.MethodPut {
		event.Operation = "upload"
		event.Filepath = r.URL.Path
		event.Filesize = contentLength
		// Case for multi-part upload
	} else if nr.Method == http.MethodPost {
		event.Operation = "multipart-upload"
		event.Filepath = r.URL.Path
		event.Filesize = contentLength
	}
	event.Username = username
	checksum.Type = "sha256"
	checksum.Value = r.Header.Get("x-amz-content-sha256")
	event.Checksum = checksum

	body, e := json.Marshal(event)
	if e != nil {
		log.Fatalf("%s", e)
	}

	corrID, _ := uuid.NewRandom()

	err := AmqpChannel.Publish(
		viper.GetString("broker.exchange"),   // publish to an exchange
		viper.GetString("broker.routingKey"), // routing to 0 or more queues
		false,                                // mandatory
		false,                                // immediate
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
