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
	"regexp"
	"strconv"
	"strings"

	"github.com/NBISweden/S3-Upload-Proxy/mq"
	"github.com/minio/minio-go/v6/pkg/s3signer"
	"github.com/spf13/viper"
	"github.com/streadway/amqp"
)

var (
	confVars = []string{
		"aws.url", "aws.accessKey", "aws.secretKey", "aws.bucket", "broker.host", "broker.port", "broker.user",
		"broker.password", "broker.vhost", "broker.exchange", "broker.routingKey", "broker.ssl", "server.users",
	}
	backedS3Url      = ""
	backedAccessKey  = ""
	backedSecretKey  = ""
	brokerHost       = ""
	brokerPort       = ""
	brokerUsername   = ""
	brokerPassword   = ""
	brokerVhost      = ""
	brokerExchange   = ""
	brokerSsl        = ""
	brokerRoutingKey = ""
	username         string
	usersMap         map[string]string
	err              error
)

var logHandle *os.File

// AmqpChannel is an AmqpChannel
var AmqpChannel *amqp.Channel

// SystemCAs holds the Ca certs from the base system
var SystemCAs, _ = x509.SystemCertPool()

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
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetConfigType("yaml")
	if viper.Get("server.confPath") != nil {
		cp := viper.Get("server.confPath").(string)
		ss := strings.Split(strings.TrimLeft(cp, "/"), "/")
		if ss[0] != "config" {
			ss = ss[:len(ss)-1]
		}
		viper.AddConfigPath(path.Join(ss...))
	}
	if err = viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			for _, s := range confVars {
				if viper.Get(s) == nil {
					panic(fmt.Errorf("%s not set", s))
				}
			}
			if viper.Get("broker.ssl") == "true" {
				if viper.Get("broker.caCert") == nil {
					panic(fmt.Errorf("broker.caCert not set"))
				}
			}
		} else {
			panic(fmt.Errorf("fatal error config file: %s", err))
		}
	}

	backedS3Url = viper.Get("aws.url").(string)
	backedAccessKey = viper.Get("aws.accessKey").(string)
	backedSecretKey = viper.Get("aws.secretKey").(string)
	brokerHost = viper.Get("broker.host").(string)
	brokerPort = viper.Get("broker.port").(string)
	brokerUsername = viper.Get("broker.user").(string)
	brokerPassword = viper.Get("broker.password").(string)
	brokerVhost = viper.Get("broker.vhost").(string)
	brokerExchange = viper.Get("broker.exchange").(string)
	brokerRoutingKey = viper.Get("broker.routingKey").(string)
	brokerSsl = viper.Get("broker.ssl").(string)

	brokerURI := mq.BuildMqURI(brokerHost, brokerPort, brokerUsername, brokerPassword, brokerVhost, brokerSsl)

	var connection *amqp.Connection

	if SystemCAs == nil {
		fmt.Println("creating new CApool")
		SystemCAs = x509.NewCertPool()
	}

	if brokerSsl == "true" {
		cfg := new(tls.Config)

		// Enforce TLS1.2 or higher
		cfg.MinVersion = 2

		cfg.RootCAs = SystemCAs

		if viper.Get("broker.serverName") != nil {
			cfg.ServerName = viper.Get("broker.serverName").(string)
		}

		if viper.Get("broker.caCert") != nil {
			cacert, e := ioutil.ReadFile(viper.Get("broker.cacert").(string))
			if e != nil {
				log.Fatalf("Failed to append %q to RootCAs: %v", cacert, err)
			}
			if ok := cfg.RootCAs.AppendCertsFromPEM(cacert); !ok {
				log.Println("No certs appended, using system certs only")
			}
		}

		if viper.Get("broker.verifyPeer").(string) == "true" {
			if viper.Get("broker.clientCert") != nil && viper.Get("broker.clientKey") != nil {
				cert, e := ioutil.ReadFile(viper.Get("broker.clientCert").(string))
				if e != nil {
					log.Fatalf("Failed to append %q to RootCAs: %v", cert, err)
				}
				key, e := ioutil.ReadFile(viper.Get("broker.clientKey").(string))
				if e != nil {
					log.Fatalf("Failed to append %q to RootCAs: %v", key, err)
				}
				if certs, e := tls.X509KeyPair(cert, key); e == nil {
					cfg.Certificates = append(cfg.Certificates, certs)
				}
			}
		}

		connection, err = mq.DialTLS(brokerURI, cfg)
		if err != nil {
			panic(fmt.Errorf("BrokerErrMsg: %s", err))
		}
	} else {
		connection, err = mq.Dial(brokerURI)
		if err != nil {
			panic(fmt.Errorf("BrokerErrMsg: %s", err))
		}
	}

	AmqpChannel, err = mq.Channel(connection)
	if err != nil {
		panic(fmt.Errorf("BrokerErrMsg: %s", err))
	}

	err = mq.Exchange(AmqpChannel, brokerExchange)
	if err != nil {
		panic(fmt.Errorf("BrokerErrMsg: %s", err))
	}

	logHandle, _ = os.Create("_requestLog.dump")

	usersMap = readUsersFile()

	http.HandleFunc("/", handler)

	if viper.Get("server.Cert") != nil && viper.Get("server.Key") != nil && viper.Get("server.Cert").(string) != "" && viper.Get("server.Key").(string) != "" {
		if e := http.ListenAndServeTLS(":8000", viper.Get("server.Cert").(string), viper.Get("server.Key").(string), nil); e != nil {
			panic(err)
		}
	} else {
		if e := http.ListenAndServe(":8000", nil); e != nil {
			panic(e)
		}
	}

	defer AmqpChannel.Close()
	defer connection.Close()

}

func readUsersFile() map[string]string {
	users := make(map[string]string)
	f, e := os.Open(viper.Get("server.users").(string))
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

func resignHeader(r *http.Request, accessKey string, secretKey string, backendURL string) *http.Request {
	if strings.Contains(backendURL, "//") {
		host := strings.SplitN(backendURL, "//", 2)
		r.Host = host[1]
	}

	return s3signer.SignV4(*r, accessKey, secretKey, "", "us-east-1")
}

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

// Extracts the signature from the authorization header
func extractSignature(r *http.Request) string {

	re := regexp.MustCompile("Signature=(.*)")
	signature := re.FindStringSubmatch(r.Header.Get("Authorization"))[1]

	return signature
}

// Authenticates the user against stored credentials
// 1) Extracts the username and retrieve the key from the map
// 2) Sign the request with the new credentials
// 3) Compare the signatures between the requests and return authentication status
func authenticateUser(r *http.Request) error {
	re := regexp.MustCompile("Credential=([^/]+)/")
	curAccessKey := re.FindStringSubmatch(r.Header.Get("Authorization"))[1]
	if curSecretKey, ok := usersMap[curAccessKey]; ok {

		if r.Method == http.MethodGet {

			signature := extractSignature(r)
			// Create signing request
			nr, e := http.NewRequest(r.Method, r.URL.String(), r.Body)
			if e != nil {
				fmt.Println(err)
			}
			// Add required headers
			nr.Header.Set("X-Amz-Date", r.Header.Get("X-Amz-Date"))
			nr.Header.Set("X-Amz-Content-Sha256", r.Header.Get("X-Amz-Content-Sha256"))
			nr.Host = r.Host
			nr.URL.RawQuery = r.URL.RawQuery
			// Sing the new request
			resignHeader(nr, curAccessKey, curSecretKey, nr.Host)
			curSignature := extractSignature(nr)
			// Compare signatures
			if curSignature != signature {
				log.Println("User signature not authenticated ", curAccessKey)
				err = fmt.Errorf("user signature not authenticated")
				return err
			}
		}
	} else {
		log.Println("User not existing: ", curAccessKey)
		err = fmt.Errorf("user not existing")
		return err
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

	if err := authenticateUser(r); err != nil {
		notAuthorized(w, r)
		return
	}
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
	bucket := viper.Get("aws.bucket").(string)
	re := regexp.MustCompile("/([^/]+)/")
	username = re.FindStringSubmatch(r.URL.Path)[1]
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
	resignHeader(r, backedAccessKey, backedSecretKey, backedS3Url)

	cfg := new(tls.Config)

	cfg.RootCAs = SystemCAs

	if viper.Get("aws.cacert") != nil {
		cacert, err := ioutil.ReadFile(viper.Get("aws.cacert").(string))
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
	nr, err := http.NewRequest(r.Method, backedS3Url+r.URL.String(), r.Body)
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

	// Send message to RabbitMQ if the upload is finished
	// TODO: Use the actual username in both cases and size, checksum for multipart upload
	if (nr.Method == http.MethodPut && response.StatusCode == 200 && !strings.Contains(nr.URL.String(), "partNumber")) ||
		(nr.Method == http.MethodPost && response.StatusCode == 200 && strings.Contains(nr.URL.String(), "uploadId")) {
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
		if e := mq.Publish(brokerExchange, brokerRoutingKey, string(body), true, AmqpChannel); e != nil {
			log.Fatalf("%s", e)
		}
	}

	// Redirect answer
	_, err = io.Copy(w, response.Body)
	if err != nil {
		log.Fatalln("redirect error")
	}
}
