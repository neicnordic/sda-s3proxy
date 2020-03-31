package main

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestTLSConfigBroker(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")
	viper.Set("broker.serverName", "RabbitMQ")

	config := NewConfig()

	assert.NotPanics(t, func() { TLSConfigBroker(config) })
	tls := TLSConfigBroker(config)
	assert.EqualValues(t, tls.ServerName, "RabbitMQ")
}

func TestTLSConfigProxy(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")

	config := NewConfig()

	assert.NotPanics(t, func() { TLSConfigProxy(config) })
	tls := TLSConfigProxy(config)
	assert.EqualValues(t, tls.ServerName, "")
}
