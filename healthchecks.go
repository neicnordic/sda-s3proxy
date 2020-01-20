package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/heptiolabs/healthcheck"
	"github.com/spf13/viper"
)

func healthchecks(port int) {
	health := healthcheck.NewHandler()

	health.AddLivenessCheck("goroutine-threshold", healthcheck.GoroutineCountCheck(100))

	upstreamURL := viper.GetString("aws.url")
	if viper.IsSet("aws.readypath") {
		upstreamURL = viper.GetString("aws.url") + viper.GetString("aws.readypath")
	}
	health.AddReadinessCheck("S3-backend-http", httpsGetCheck(upstreamURL, 5000*time.Millisecond))

	brokerURL := viper.GetString("broker.host") + ":" + viper.GetString("broker.port")
	health.AddReadinessCheck(
		"broker-tcp",
		healthcheck.TCPDialCheck(brokerURL, 50*time.Millisecond))

	addr := ":" + strconv.Itoa(port)

	if err = http.ListenAndServe(addr, health); err != nil {
		panic(err)
	}
}

func httpsGetCheck(url string, timeout time.Duration) healthcheck.Check {
	cfg := &tls.Config{}
	cfg.RootCAs = SystemCAs
	tr := &http.Transport{TLSClientConfig: cfg}
	client := http.Client{
		Transport: tr,
		Timeout:   timeout,
		// never follow redirects
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return func() error {
		resp, e := client.Get(url)
		if e != nil {
			return e
		}
		_ = resp.Body.Close() //ignoring error
		if resp.StatusCode != 200 {
			return fmt.Errorf("returned status %d", resp.StatusCode)
		}
		return nil
	}
}
