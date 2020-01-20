package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestHttpsGetCheck(t *testing.T) {
	assert.NoError(t, httpsGetCheck("https://www.nbis.se", 5*time.Second)())
	assert.Error(t, httpsGetCheck("https://www.nbis.se/nonexistent", 5*time.Second)(), "404 should fail")

}

func TestHealthchecks(t *testing.T) {
	viper.Reset()
	viper.Set("aws.url", "http://localhost:8080")
	viper.Set("aws.readypath", "/")
	viper.Set("aws.accessKey", "")
	viper.Set("aws.secretKey", "")
	viper.Set("aws.bucket", "")
	viper.Set("broker.host", "localhost")
	viper.Set("broker.port", "8080")
	viper.Set("broker.user", "")
	viper.Set("broker.password", "")
	viper.Set("broker.vhost", "")
	viper.Set("broker.exchange", "")
	viper.Set("broker.routingKey", "")
	viper.Set("broker.ssl", "")
	viper.Set("server.users", "")

	l, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}
	foo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	ts := httptest.NewUnstartedServer(foo)
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()

	go healthchecks(8888)

	time.Sleep(100 * time.Millisecond)

	res, err := http.Get("http://localhost:8888/ready?full=1")
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("greeting: %s", body)

	if res.StatusCode != http.StatusOK {
		t.Errorf("Response code was %v; want 200", res.StatusCode)
	}

	ts.Close()
}
