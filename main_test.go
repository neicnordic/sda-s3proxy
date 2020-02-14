package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v6/pkg/s3signer"
	"github.com/spf13/viper"
	"github.com/streadway/amqp"
	"github.com/stretchr/testify/assert"
)

func TestNotAuthorized(t *testing.T) {
	r, _ := http.NewRequest("", "", strings.NewReader(""))
	w := httptest.NewRecorder()
	notAuthorized(w, r)
	assert.Equal(t, 401, w.Result().StatusCode)
}

func TestNotAllowedResponse(t *testing.T) {
	r, _ := http.NewRequest("", "", strings.NewReader(""))
	w := httptest.NewRecorder()
	notAllowedResponse(w, r)
	assert.Equal(t, 403, w.Result().StatusCode)
}

func TestConfirmOne(t *testing.T) {
	fmt.Println("Test main.confirmOne")
	rwc, srv := newSession(t)

	go func() {
		srv.connectionOpen()
		srv.channelOpen(1)
		srv.recv(1, &confirmSelect{})
		srv.send(1, &confirmSelectOk{})

		srv.recv(1, &basicPublish{})
		srv.send(1, &basicAck{DeliveryTag: 1})

		srv.recv(1, &basicPublish{})
		srv.send(1, &basicNack{DeliveryTag: 2})
	}()

	c, _ := amqp.Open(rwc, defaultConfig())
	defer c.Close()

	ch, _ := c.Channel()
	ch.Confirm(true)
	defer ch.Close()

	confirms := ch.NotifyPublish(make(chan amqp.Confirmation, 2))

	msg := amqp.Publishing{
		DeliveryMode: amqp.Transient,
		Timestamp:    time.Now(),
		ContentType:  "text/plain",
		Body:         []byte("Test"),
	}

	ch.Publish(
		"",
		"k",
		false,
		false,
		amqp.Publishing{
			Body: msg.Body,
		},
	)
	assert.NoError(t, confirmOne(confirms))

	ch.Publish(
		"",
		"k",
		false,
		false,
		amqp.Publishing{
			Body: msg.Body,
		},
	)
	assert.Error(t, confirmOne(confirms))
	rwc.Close()
}

func TestResignHeader(t *testing.T) {
	fmt.Println("test main.resignHeader")
	s, _ := http.NewRequest("", "", strings.NewReader(""))
	s.Host = "localhost"
	sig := s3signer.SignV4(*s, "accessKey", "secretKey", "", "us-west-1")

	viper.Set("aws.region", "us-west-1")
	r, _ := http.NewRequest("", "", strings.NewReader(""))
	resignHeader(r, "accessKey", "secretKey", "http://localhost")
	assert.Equal(t, r.Header.Get("Authorization"), sig.Header.Get("Authorization"))

	resignHeader(r, "accessKey", "differentKey", "http://localhost")
	assert.NotEqual(t, r.Header.Get("Authorization"), sig.Header.Get("Authorization"))
}
func TestDetectRequestType(t *testing.T) {
	r, _ := http.NewRequest("GET", "", strings.NewReader(""))
	list := detectRequestType(r)
	assert.Equal(t, S3RequestType(2), list)

	r.URL.Path = "localhost/"
	get := detectRequestType(r)
	assert.Equal(t, S3RequestType(4), get)

	r.URL.RawQuery = "acl"
	policy := detectRequestType(r)
	assert.Equal(t, S3RequestType(7), policy)

	r.Method = "DELETE"
	r.URL.RawQuery = ""
	rb := detectRequestType(r)
	assert.Equal(t, S3RequestType(1), rb)

	r.Method = "DELETE"
	r.URL.Path = "uploadId"
	abort := detectRequestType(r)
	assert.Equal(t, S3RequestType(6), abort)

	r.Method = "DELETE"
	r.URL.Path = ""
	del := detectRequestType(r)
	assert.Equal(t, S3RequestType(5), del)

	r.Method = "PUT"
	r.URL.Path = "/"
	mb := detectRequestType(r)
	assert.Equal(t, S3RequestType(0), mb)

	r.Method = "PUT"
	r.URL.RawQuery = "policy"
	p := detectRequestType(r)
	assert.Equal(t, S3RequestType(7), p)

	r.Method = "PUT"
	r.URL.Path = "localhost"
	r.URL.RawQuery = ""
	put := detectRequestType(r)
	assert.Equal(t, S3RequestType(3), put)

	r.Method = ""
	r.URL.Path = ""
	other := detectRequestType(r)
	assert.Equal(t, S3RequestType(8), other)
}

func TestAuthenticateUser(t *testing.T) {
	fmt.Println("test main.authenticateUser")
	viper.Reset()
	viper.Set("server.users", "dev_utils/users.csv")
	// no authentication header
	r, _ := http.NewRequest("GET", "", strings.NewReader(""))
	assert.Error(t, authenticateUser(r))

	// correct path
	r.URL.Path = "/dummy/"
	r.Header.Set("Authorization", "Credential=dummy/aws4_request")
	assert.Error(t, authenticateUser(r))

	// wrong path
	r.URL.Path = "/wrong-path/?"
	r.Header.Set("Authorization", "Credential=dummy/aws4_request")
	assert.Error(t, authenticateUser(r))

	// no signature
	r.URL.Path = "/username/"
	r.Header.Set("Authorization", "Credential=username/aws4_request")
	assert.Error(t, authenticateUser(r))

	// wrong signature
	r.Header.Set("Authorization", "Credential=username/aws4_request,Signature=d62ca288cb869cbfcaddfac5e7e078280f70294731205428b231dcb97dd5f245")
	assert.Error(t, authenticateUser(r))

	// correct signature
	q, _ := http.NewRequest("GET", "/username/", strings.NewReader(""))
	q.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	q.Header.Set("X-Amz-Content-Sha256", "")

	s, _ := http.NewRequest("GET", "/username/", strings.NewReader(""))
	s.Header.Set("X-Amz-Date", q.Header.Get("X-Amz-Date"))
	s.Header.Set("X-Amz-Content-Sha256", q.Header.Get("X-Amz-Content-Sha256"))
	resignHeader(s, "username", "testpass", q.Host)
	re := regexp.MustCompile("Signature=(.*)")
	sig := re.FindStringSubmatch(s.Header.Get("Authorization"))
	header := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=username/%s/us-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", time.Now().UTC().Format("20060102"), sig[1])
	q.Header.Set("Authorization", header)
	assert.NoError(t, authenticateUser(q))
}

func TestAllowedResponse(t *testing.T) {
	fmt.Println("test main.allowedResponse")

	l, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}
	foo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	ts := httptest.NewUnstartedServer(foo)
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()

	viper.Reset()
	viper.Set("server.users", "dev_utils/users.csv")
	viper.Set("aws.url", "http://localhost:8080")
	viper.Set("aws.bucket", "test")
	viper.Set("aws.cacert", "dev_utils/certs/ca.crt")

	r, _ := http.NewRequest("GET", "/username/", strings.NewReader(""))
	w := httptest.NewRecorder()

	// not authorized
	fmt.Println("not authorized")
	allowedResponse(w, r)
	assert.Equal(t, 401, w.Result().StatusCode)

	// authorized ?location
	fmt.Println("authorized")
	w = httptest.NewRecorder()
	q, _ := http.NewRequest("GET", "/username/", strings.NewReader(""))
	q.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	q.Header.Set("X-Amz-Content-Sha256", "")
	q.URL.RawQuery = "location"

	s, _ := http.NewRequest("GET", q.URL.Path, strings.NewReader(""))
	s.Header.Set("X-Amz-Date", q.Header.Get("X-Amz-Date"))
	s.Header.Set("X-Amz-Content-Sha256", q.Header.Get("X-Amz-Content-Sha256"))
	s.URL.RawQuery = q.URL.RawQuery
	resignHeader(s, "username", "testpass", q.Host)
	re := regexp.MustCompile("Signature=(.*)")
	sig := re.FindStringSubmatch(s.Header.Get("Authorization"))
	header := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=username/%s/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", time.Now().UTC().Format("20060102"), sig[1])

	q.Header.Set("Authorization", header)
	allowedResponse(w, q)
	assert.Equal(t, 200, w.Result().StatusCode)

	// authorized ?delimiter
	w = httptest.NewRecorder()
	q, _ = http.NewRequest("GET", "/username/", strings.NewReader(""))
	q.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	q.Header.Set("X-Amz-Content-Sha256", "")
	q.URL.RawQuery = "delimiter"

	s, _ = http.NewRequest("GET", q.URL.Path, strings.NewReader(""))
	s.Header.Set("X-Amz-Date", q.Header.Get("X-Amz-Date"))
	s.Header.Set("X-Amz-Content-Sha256", q.Header.Get("X-Amz-Content-Sha256"))
	s.URL.RawQuery = q.URL.RawQuery
	resignHeader(s, "username", "testpass", q.Host)
	re = regexp.MustCompile("Signature=(.*)")
	sig = re.FindStringSubmatch(s.Header.Get("Authorization"))
	header = fmt.Sprintf("AWS4-HMAC-SHA256 Credential=username/%s/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", time.Now().UTC().Format("20060102"), sig[1])

	q.Header.Set("Authorization", header)
	allowedResponse(w, q)
	assert.Equal(t, 200, w.Result().StatusCode)

	// authorized ?delimiter &prefix=
	w = httptest.NewRecorder()
	q, _ = http.NewRequest("GET", "/username/", strings.NewReader(""))
	q.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	q.Header.Set("X-Amz-Content-Sha256", "")
	q.URL.RawQuery = "delimiter&prefix="

	s, _ = http.NewRequest("GET", q.URL.Path, strings.NewReader(""))
	s.Header.Set("X-Amz-Date", q.Header.Get("X-Amz-Date"))
	s.Header.Set("X-Amz-Content-Sha256", q.Header.Get("X-Amz-Content-Sha256"))
	s.URL.RawQuery = q.URL.RawQuery
	resignHeader(s, "username", "testpass", q.Host)
	re = regexp.MustCompile("Signature=(.*)")
	sig = re.FindStringSubmatch(s.Header.Get("Authorization"))
	header = fmt.Sprintf("AWS4-HMAC-SHA256 Credential=username/%s/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", time.Now().UTC().Format("20060102"), sig[1])

	q.Header.Set("Authorization", header)
	allowedResponse(w, q)
	assert.Equal(t, 200, w.Result().StatusCode)

	// authorized PUT
	viper.Set("broker.host", "localhost")

	rwc, srv := newSession(t)
	go func() {
		srv.connectionOpen()
		srv.channelOpen(1)
		srv.recv(1, &confirmSelect{})
		srv.send(1, &confirmSelectOk{})

		srv.recv(1, &basicPublish{})
		srv.send(1, &basicAck{DeliveryTag: 1})

	}()
	c, _ := amqp.Open(rwc, defaultConfig())
	defer c.Close()

	AmqpChannel, _ = c.Channel()
	defer AmqpChannel.Close()

	w = httptest.NewRecorder()
	q, _ = http.NewRequest("PUT", "/username/", strings.NewReader(""))
	q.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	q.Header.Set("X-Amz-Content-Sha256", "")

	s, _ = http.NewRequest("GET", q.URL.Path, strings.NewReader(""))
	s.Header.Set("X-Amz-Date", q.Header.Get("X-Amz-Date"))
	s.Header.Set("X-Amz-Content-Sha256", q.Header.Get("X-Amz-Content-Sha256"))
	s.URL.RawQuery = q.URL.RawQuery
	resignHeader(s, "username", "testpass", q.Host)
	re = regexp.MustCompile("Signature=(.*)")
	sig = re.FindStringSubmatch(s.Header.Get("Authorization"))
	header = fmt.Sprintf("AWS4-HMAC-SHA256 Credential=username/%s/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", time.Now().UTC().Format("20060102"), sig[1])

	q.Header.Set("Authorization", header)
	allowedResponse(w, q)
	assert.Equal(t, 200, w.Result().StatusCode)
	rwc.Close()
}

func TestHandler(t *testing.T) {
	fmt.Println("test handler")
	viper.Reset()
	// default response
	fmt.Println("Default")
	d, _ := http.NewRequest("GET", "localhost/?acl", strings.NewReader(""))
	fmt.Println("PATH:", d.URL.Path)
	fmt.Println("PATH:", d.URL.RawQuery)
	w1 := httptest.NewRecorder()
	handler(w1, d)
	assert.Equal(t, 403, w1.Result().StatusCode)

	// case Delete
	fmt.Println("Delete")
	p, _ := http.NewRequest("DELETE", "", strings.NewReader(""))
	w2 := httptest.NewRecorder()
	handler(w2, p)
	assert.Equal(t, 403, w2.Result().StatusCode)

	// Put
	fmt.Println("Put")
	rwc, srv := newSession(t)
	go func() {
		srv.connectionOpen()
		srv.channelOpen(1)
		srv.recv(1, &confirmSelect{})
		srv.send(1, &confirmSelectOk{})

		srv.recv(1, &basicPublish{})
		srv.send(1, &basicAck{DeliveryTag: 1})

	}()
	c, _ := amqp.Open(rwc, defaultConfig())
	defer c.Close()

	AmqpChannel, _ = c.Channel()
	defer AmqpChannel.Close()

	w3 := httptest.NewRecorder()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	viper.Set("server.users", "dev_utils/users.csv")
	viper.Set("aws.url", ts.URL)

	q, _ := http.NewRequest("PUT", "/username/file", strings.NewReader(""))
	q.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	q.Header.Set("X-Amz-Content-Sha256", "")
	fmt.Println(q.URL.Path)

	s, _ := http.NewRequest("PUT", q.URL.String(), strings.NewReader(""))
	s.Header.Set("X-Amz-Date", q.Header.Get("X-Amz-Date"))
	s.Header.Set("X-Amz-Content-Sha256", q.Header.Get("X-Amz-Content-Sha256"))
	s.URL.RawQuery = q.URL.RawQuery

	resignHeader(s, "username", "testpass", q.Host)
	re := regexp.MustCompile("Signature=(.*)")
	sig := re.FindStringSubmatch(s.Header.Get("Authorization"))
	header := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=username/%s/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", time.Now().UTC().Format("20060102"), sig[1])
	q.Header.Set("Authorization", header)

	handler(w3, q)
	assert.Equal(t, 200, w3.Result().StatusCode)
	rwc.Close()
}
