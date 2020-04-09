package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go/v6/pkg/s3signer"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Proxy represents the toplevel object in this application
type Proxy struct {
	s3        S3Config
	auth      Authenticator
	messenger Messenger
	tlsConfig *tls.Config
}

// S3RequestType is the type of request that we are currently proxying to the
// backend
type S3RequestType int

// The different types of requests
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

// NewProxy creates a new S3Proxy. This implements the ServerHTTP interface.
func NewProxy(s3conf S3Config, auth Authenticator, messenger Messenger, tls *tls.Config) *Proxy {
	log.SetLevel(log.InfoLevel)
	return &Proxy{s3conf, auth, messenger, tls}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch t := p.detectRequestType(r); t {
	case MakeBucket, RemoveBucket, Delete, Policy, Get:
		// Not allowed
		log.Debug("Not allowed 1")
		p.notAllowedResponse(w, r)
	case Put, List, Other, AbortMultipart:
		// Allowed
		p.allowedResponse(w, r)
	default:
		log.Debug("Not allowed 2")
		p.notAllowedResponse(w, r)
	}
}

func (p *Proxy) internalServerError(w http.ResponseWriter, r *http.Request) {
	log.Debug("Internal Server Error")
	w.WriteHeader(500)
}

func (p *Proxy) notAllowedResponse(w http.ResponseWriter, r *http.Request) {
	log.Debug("Not Allowed Response")
	w.WriteHeader(403)
}

func (p *Proxy) notAuthorized(w http.ResponseWriter, r *http.Request) {
	log.Debug("Not Authorized")
	w.WriteHeader(401) // Actually correct!
}

func (p *Proxy) allowedResponse(w http.ResponseWriter, r *http.Request) {
	if err := p.auth.Authenticate(r); err != nil {
		log.Debug("Not authenticated !!!!!! !!  !!!")
		log.Debug(err)
		p.notAuthorized(w, r)
		return
	}

	log.Debug("Prepend")
	p.prependBucketToHostPath(r)

	log.Debug("Forward to Backend")
	s3response, err := p.forwardToBackend(r)

	if err != nil {
		log.Debug("Internal server error")
		fmt.Println(err)
		p.internalServerError(w, r)
		return
	}

	// Send message to upstream
	if p.uploadFinishedSuccessfully(r, s3response) {
		message, _ := p.CreateMessageFromRequest(r)
		if err = p.messenger.SendMessage(message); err != nil {
			log.Printf("error when sending message: %v", err)
		}
	}

	// Redirect answer
	for header, values := range s3response.Header {
		for _, value := range values {
			w.Header().Add(header, value)
		}
	}
	_, err = io.Copy(w, s3response.Body)
	if err != nil {
		log.Fatalln("redirect error")
	}
}

func (p *Proxy) uploadFinishedSuccessfully(req *http.Request, response *http.Response) bool {
	if response.StatusCode != 200 {
		return false
	} else if req.Method == http.MethodPut && !strings.Contains(req.URL.String(), "partNumber") {
		return true
	} else if req.Method == http.MethodPost && strings.Contains(req.URL.String(), "uploadId") {
		return true
	} else {
		return false
	}
}

func (p *Proxy) forwardToBackend(r *http.Request) (*http.Response, error) {
	tr := &http.Transport{TLSClientConfig: p.tlsConfig}
	client := &http.Client{Transport: tr}

	p.resignHeader(r, p.s3.accessKey, p.s3.secretKey, p.s3.url)

	// Redirect request
	nr, err := http.NewRequest(r.Method, p.s3.url+r.URL.String(), r.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	nr.Header = r.Header
	contentLength, _ := strconv.ParseInt(r.Header.Get("content-length"), 10, 64)
	nr.ContentLength = contentLength
	return client.Do(nr)
}

// Add bucket to host path
func (p *Proxy) prependBucketToHostPath(r *http.Request) {
	bucket := p.s3.bucket

	// Extract username for request's url path
	re := regexp.MustCompile("/([^/]+)/")
	username := re.FindStringSubmatch(r.URL.Path)[1]

	log.Debug("Incomming Path: ", r.URL.Path)
	log.Debug("Incomming Raw: ", r.URL.RawQuery)

	// Restructure request to query the users folder instead of the general bucket
	if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "?delimiter") {
		r.URL.Path = "/" + bucket + "/"
		if strings.Contains(r.URL.RawQuery, "&prefix") {
			params := strings.Split(r.URL.RawQuery, "&prefix=")
			r.URL.RawQuery = params[0] + "&prefix=" + username + "%2F" + params[1]
		} else {
			r.URL.RawQuery = r.URL.RawQuery + "&prefix=" + username + "%2F"
		}
		log.Debug("New RawQuery: ", r.URL.RawQuery)
	} else if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "?location") {
		r.URL.Path = "/" + bucket + "/"
		log.Debug("New Path: ", r.URL.Path)
	} else if r.Method == http.MethodPost || r.Method == http.MethodPut {
		r.URL.Path = "/" + bucket + r.URL.Path
		log.Debug("New Path: ", r.URL.Path)
	}
}

// Function for signing the headers of the s3 requests
// Used for for creating a signature for with the default
// credentials of the s3 service and the user's signature (authentication)
func (p *Proxy) resignHeader(r *http.Request, accessKey string, secretKey string, backendURL string) *http.Request {
	r.Header.Del("X-Amz-Security-Token")
	if strings.Contains(backendURL, "//") {
		host := strings.SplitN(backendURL, "//", 2)
		r.Host = host[1]
	}
	return s3signer.SignV4(*r, accessKey, secretKey, "", p.s3.region)
}

// Not necessarily a function on the struct since it does not use any of the
// members.
func (p *Proxy) detectRequestType(r *http.Request) S3RequestType {
	switch r.Method {
	case http.MethodGet:
		if strings.HasSuffix(r.URL.String(), "/") {
			log.Debug("detect Get")
			return Get
		} else if strings.Contains(r.URL.String(), "?acl") {
			log.Debug("detect Policy")
			return Policy
		} else {
			log.Debug("detect List")
			return List
		}
	case http.MethodDelete:
		if strings.HasSuffix(r.URL.String(), "/") {
			log.Debug("detect RemoveBucket")
			return RemoveBucket
		} else if strings.Contains(r.URL.String(), "uploadId") {
			log.Debug("detect AbortMultipart")
			return AbortMultipart
		} else {
			// Do we allow deletion of files?
			log.Debug("detect Delete")
			return Delete
		}
	case http.MethodPut:
		if strings.HasSuffix(r.URL.String(), "/") {
			log.Debug("detect MakeBucket")
			return MakeBucket
		} else if strings.Contains(r.URL.String(), "?policy") {
			log.Debug("detect Policy")
			return Policy
		} else {
			// Should decide if we will handle copy here or through authentication
			log.Debug("detect Put")
			return Put
		}
	default:
		log.Debug("detect Other")
		return Other
	}
}

// CreateMessageFromRequest is a function that can take a http request and
// figure out the correct message to send from it.
func (p *Proxy) CreateMessageFromRequest(r *http.Request) (Event, error) {
	// Extract username for request's url path
	re := regexp.MustCompile("/[^/]+/([^/]+)/")
	username := re.FindStringSubmatch(r.URL.Path)[1]

	event := Event{}
	checksum := Checksum{}
	var err error

	checksum.Value, event.Filesize, err = p.requestInfo(r.URL.Path)
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
	log.Info("%v uploaded %v on %v", event.Username, event.Filepath, time.Now())
	return event, nil
}

// RequestInfo is a function that makes a request to the S3 and collects
// the etag and size information for the uploaded document
func (p *Proxy) requestInfo(fullPath string) (string, int64, error) {
	filePath := strings.Replace(fullPath, "/"+viper.GetString("aws.bucket"), "", 1)
	s, err := p.newSession()
	if err != nil {
		return "", 0, err
	}
	svc := s3.New(s)
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(p.s3.bucket),
		MaxKeys: aws.Int64(1),
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
		return "", 0, err
	}
	return strings.ReplaceAll(*result.Contents[0].ETag, "\"", ""), *result.Contents[0].Size, nil
}

func (p *Proxy) newSession() (*session.Session, error) {
	var mySession *session.Session
	var err error
	if p.s3.cacert != "" {
		cert, _ := ioutil.ReadFile(p.s3.cacert)
		cacert := bytes.NewReader(cert)
		mySession, err = session.NewSessionWithOptions(session.Options{
			CustomCABundle: cacert,
			Config: aws.Config{
				Region:           aws.String(p.s3.region),
				Endpoint:         aws.String(p.s3.url),
				DisableSSL:       aws.Bool(strings.HasPrefix(p.s3.url, "http:")),
				S3ForcePathStyle: aws.Bool(true),
				Credentials:      credentials.NewStaticCredentials(p.s3.accessKey, p.s3.secretKey, ""),
			}})
		if err != nil {
			return nil, err
		}
	} else {
		mySession, err = session.NewSession(&aws.Config{
			Region:           aws.String(p.s3.region),
			Endpoint:         aws.String(p.s3.url),
			DisableSSL:       aws.Bool(strings.HasPrefix(p.s3.url, "http:")),
			S3ForcePathStyle: aws.Bool(true),
			Credentials:      credentials.NewStaticCredentials(p.s3.accessKey, p.s3.secretKey, ""),
		})
		if err != nil {
			return nil, err
		}
	}
	return mySession, nil
}
