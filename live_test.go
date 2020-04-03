// +build live
// This test assumes that the dev_utils docker-compose services are running

package main

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewAMQPMessenger(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")

	config := NewConfig()
	tlsConfig := TLSConfigBroker(config)

	assert.NotPanics(t, func() { NewAMQPMessenger(config.Broker, tlsConfig) })
}

func TestSendMessage(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")

	config := NewConfig()
	tlsConfig := TLSConfigBroker(config)
	messenger := NewAMQPMessenger(config.Broker, tlsConfig)

	event := Event{}
	checksum := Checksum{}
	event.Username = "Dummy"
	checksum.Type = "etag"
	checksum.Value = "123456789"
	event.Checksum = checksum

	assert.NotPanics(t, func() { messenger.SendMessage(event) })

}

func TestMain(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")
	timeout := time.After(1 * time.Second)
	done := make(chan bool)
	go func() {
		assert.NotPanics(t, func() { main() })
	}()
	select {
	case <-timeout:
		t.Log("Killing the main function")
	case <-done:
	}
}
