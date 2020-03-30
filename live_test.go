// +build live

package main

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewAMQPMessenger(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")

	config := NewConfig()
	tlsConfig := TLSConfig(config)

	assert.NotPanics(t, func() { NewAMQPMessenger(config.Broker, tlsConfig) })
}

func TestSendMessage(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")

	config := NewConfig()
	tlsConfig := TLSConfig(config)
	messenger := NewAMQPMessenger(config.Broker, tlsConfig)

	event := Event{}
	checksum := Checksum{}
	event.Username = "Dummy"
	checksum.Type = "etag"
	checksum.Value = "123456789"
	event.Checksum = checksum

	assert.NotPanics(t, func() { messenger.SendMessage(event) })

}
