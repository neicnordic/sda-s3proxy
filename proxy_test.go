package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

type FakeServer struct {
	ts     *httptest.Server
	resp   string
	pinged bool
}

func startFakeServer(port string) *FakeServer {
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(fmt.Errorf("Can't create mock server for testing: %s", err))
	}
	f := FakeServer{}
	foo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.pinged = true
		fmt.Fprintf(w, f.resp)
	})
	ts := httptest.NewUnstartedServer(foo)
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()

	f.ts = ts

	return &f
}

func (f *FakeServer) Close() {
	f.ts.Close()
}

func (f *FakeServer) PingedAndRestore() bool {
	ret := f.pinged
	f.pinged = false
	return ret
}

type MockMessenger struct {
	lastEvent *Event
}

func NewMockMessenger() *MockMessenger {
	return &MockMessenger{nil}
}

func (m *MockMessenger) SendMessage(event Event) error {
	m.lastEvent = &event
	return nil
}

func (m *MockMessenger) CheckAndRestore() bool {
	if m.lastEvent == nil {
		return false
	}
	m.lastEvent = nil
	return true
}

// AlwaysAllow is an Authenticator that always authenticates
type AlwaysDeny struct{}

// Authenticate authenticates everyone.
func (u *AlwaysDeny) Authenticate(r *http.Request) error {
	return fmt.Errorf("denied")
}

func TestServeHTTP_disallowed(t *testing.T) {
	// Start fake server
	f := startFakeServer("9023")
	defer f.Close()

	s3conf := S3Config{
		url:       "http://localhost:9023",
		accessKey: "someAccess",
		secretKey: "someSecret",
		bucket:    "buckbuck",
		region:    "us-east-1",
		cacert:    "./dev_utils/certs/ca.crt",
	}
	messenger := NewMockMessenger()
	proxy := NewProxy(s3conf, &AlwaysDeny{}, messenger, new(tls.Config))

	r, _ := http.NewRequest("", "", nil)
	w := httptest.NewRecorder()

	// Remove bucket disallowed
	r.Method = "DELETE"
	r.URL, _ = url.Parse("/asdf/")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Result().StatusCode)
	assert.Equal(t, false, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Deletion of files are disallowed
	r.Method = "DELETE"
	r.URL, _ = url.Parse("/asdf/asdf")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Result().StatusCode)
	assert.Equal(t, false, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Policy methods are not allowed
	w = httptest.NewRecorder()
	r.Method = "GET"
	r.URL, _ = url.Parse("/asdf?acl=rw")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Result().StatusCode)
	assert.Equal(t, false, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Normal get is dissallowed
	w = httptest.NewRecorder()
	r.Method = "GET"
	r.URL, _ = url.Parse("/asdf/")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Result().StatusCode)
	assert.Equal(t, false, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Put policy is disallowed
	w = httptest.NewRecorder()
	r.Method = "PUT"
	r.URL, _ = url.Parse("/asdf?policy=rw")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Result().StatusCode)
	assert.Equal(t, false, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Create bucket disallowed
	w = httptest.NewRecorder()
	r.Method = "PUT"
	r.URL, _ = url.Parse("/asdf/")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 403, w.Result().StatusCode)
	assert.Equal(t, false, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Not authorized user get 401 response
	w = httptest.NewRecorder()
	r.Method = "GET"
	r.URL, _ = url.Parse("/username/file")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 401, w.Result().StatusCode)
	assert.Equal(t, false, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())
}

func TestServeHTTP_S3Unresponsive(t *testing.T) {
	s3conf := S3Config{
		url:       "http://localhost:40211",
		accessKey: "someAccess",
		secretKey: "someSecret",
		bucket:    "buckbuck",
		region:    "us-east-1",
		cacert:    "./dev_utils/certs/ca.crt",
	}
	messenger := NewMockMessenger()
	proxy := NewProxy(s3conf, &AlwaysAllow{}, messenger, new(tls.Config))

	r, _ := http.NewRequest("", "", nil)
	w := httptest.NewRecorder()

	// Just try to list the files
	r.Method = "GET"
	r.URL, _ = url.Parse("/asdf/asdf")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 500, w.Result().StatusCode)
	assert.Equal(t, false, messenger.CheckAndRestore())
}

func TestServeHTTP_allowed(t *testing.T) {
	// Start fake server
	f := startFakeServer("9024")
	defer f.Close()

	// Start proxy
	s3conf := S3Config{
		url:       "http://localhost:9024",
		accessKey: "someAccess",
		secretKey: "someSecret",
		bucket:    "buckbuck",
		region:    "us-east-1",
		cacert:    "./dev_utils/certs/ca.crt",
	}
	messenger := NewMockMessenger()
	proxy := NewProxy(s3conf, NewAlwaysAllow(), messenger, new(tls.Config))
	//proxy := NewProxy(s3conf, NewValidateFromFile("./dev_utils/users.csv"), NewMockMessenger(), s, new(tls.Config))

	// List files works
	r, _ := http.NewRequest("GET", "/username/file", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, false, f.PingedAndRestore()) // Testing the pinged interface
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Put file works
	w = httptest.NewRecorder()
	r.Method = "PUT"
	f.resp = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>test</Name><Prefix>/elexirid/file.txt</Prefix><KeyCount>1</KeyCount><MaxKeys>2</MaxKeys><Delimiter></Delimiter><IsTruncated>false</IsTruncated><Contents><Key>/elexirid/file.txt</Key><LastModified>2020-03-10T13:20:15.000Z</LastModified><ETag>&#34;0a44282bd39178db9680f24813c41aec-1&#34;</ETag><Size>5</Size><Owner><ID></ID><DisplayName></DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, true, messenger.CheckAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Put with partnumber sends no message
	w = httptest.NewRecorder()
	r.Method = "PUT"
	r.URL, _ = url.Parse("/username/file?partNumber=5")
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Post with uploadId sends message
	r.Method = "POST"
	r.URL, _ = url.Parse("/username/file?uploadId=5")
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, true, messenger.CheckAndRestore())

	// Post without uploadId sends no message
	r.Method = "POST"
	r.URL, _ = url.Parse("/username/file")
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Abort multipart works
	r.Method = "DELETE"
	r.URL, _ = url.Parse("/asdf/asdf?uploadId=123")
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Going through the different extra stuff that can be in the get request
	// that trigger different code paths in the code.
	// Delimiter alone
	r.Method = "GET"
	r.URL, _ = url.Parse("/username/file?delimiter=puppe")
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Delimiter alone together with prefix
	r.Method = "GET"
	r.URL, _ = url.Parse("/username/file?delimiter=puppe&prefix=asdf")
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())

	// Location parameter
	r.Method = "GET"
	r.URL, _ = url.Parse("/username/file?location=fnuffe")
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.Equal(t, true, f.PingedAndRestore())
	assert.Equal(t, false, messenger.CheckAndRestore())
}

func TestMessageFormatting(t *testing.T) {
	f := startFakeServer("9023")
	// Set up basic request for multipart upload
	r, _ := http.NewRequest("POST", "/buckbuck/user/new_file.txt", nil)
	r.Host = "localhost"
	r.Header.Set("content-length", "1234")
	r.Header.Set("x-amz-content-sha256", "checksum")

	s3conf := S3Config{
		url:       "http://localhost:9023",
		accessKey: "someAccess",
		secretKey: "someSecret",
		bucket:    "buckbuck",
		region:    "us-east-1",
		cacert:    "./dev_utils/certs/ca.crt",
	}
	messenger := NewMockMessenger()
	proxy := NewProxy(s3conf, &AlwaysDeny{}, messenger, new(tls.Config))
	f.resp = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>test</Name><Prefix>/user/new_file.txt</Prefix><KeyCount>1</KeyCount><MaxKeys>2</MaxKeys><Delimiter></Delimiter><IsTruncated>false</IsTruncated><Contents><Key>/user/new_file.txt</Key><LastModified>2020-03-10T13:20:15.000Z</LastModified><ETag>&#34;0a44282bd39178db9680f24813c41aec-1&#34;</ETag><Size>1234</Size><Owner><ID></ID><DisplayName></DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"
	msg, err := proxy.CreateMessageFromRequest(r)
	assert.Nil(t, err)
	assert.IsType(t, Event{}, msg)

	assert.Equal(t, "multipart-upload", msg.Operation)
	assert.Equal(t, int64(1234), msg.Filesize)
	assert.Equal(t, "/buckbuck/user/new_file.txt", msg.Filepath)
	assert.Equal(t, "user", msg.Username)
	assert.Equal(t, "etag", msg.Checksum.Type)
	assert.Equal(t, "0a44282bd39178db9680f24813c41aec-1", msg.Checksum.Value)

	// Test single shot upload
	r.Method = "PUT"
	msg, err = proxy.CreateMessageFromRequest(r)
	assert.Nil(t, err)
	assert.IsType(t, Event{}, msg)
	assert.Equal(t, "upload", msg.Operation)

	// Test GET upload
	r.Method = "GET"
	msg, err = proxy.CreateMessageFromRequest(r)
	assert.NotNil(t, err)
	assert.IsType(t, Event{}, msg)
	assert.Equal(t, "", msg.Operation)
}
