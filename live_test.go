// +build live
// This test assumes that the dev_utils docker-compose services are running

package main

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewAMQPMessenger(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")

	config, err := NewConfig()
	assert.NotNil(t, config)
	assert.NoError(t, err)
	tlsConfig, err := TLSConfigBroker(config)
	assert.NotNil(t, tlsConfig)
	assert.NoError(t, err)

	assert.NotPanics(t, func() { NewAMQPMessenger(config.Broker, tlsConfig) })
}

func TestSendMessage(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")

	config, err := NewConfig()
	assert.NotNil(t, config)
	assert.NoError(t, err)
	tlsConfig, err := TLSConfigBroker(config)
	assert.NotNil(t, tlsConfig)
	assert.NoError(t, err)

	messenger := NewAMQPMessenger(config.Broker, tlsConfig)

	event := Event{}
	checksum := Checksum{}
	event.Username = "Dummy"
	checksum.Type = "md5"
	checksum.Value = "123456789"
	event.Checksum = []interface{}{checksum}

	assert.NotPanics(t, func() { messenger.SendMessage(event) })

}
