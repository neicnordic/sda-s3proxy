package main

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestInitialization_NoConfig(t *testing.T) {
	viper.Reset()
	assert.Panics(t, func() { NewConfig() })
}

func TestInitialization_confPath(t *testing.T) {
	viper.Reset()
	viper.Set("server.confPath", "dev_utils/")
	assert.NotPanics(t, func() { NewConfig() })
}

func TestInitialization_WrongConfFile(t *testing.T) {
	viper.Reset()
	viper.SetConfigType("")
	viper.Set("server.confFile", "dev_utils/certs/ca.crt")
	assert.Panics(t, func() { NewConfig() })
}

func TestInitialization_ConfFile(t *testing.T) {
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")
	assert.NotPanics(t, func() { NewConfig() })
}

func TestInitialization_OnlyrequiredAttributesWithFile(t *testing.T) {
	viper.Reset()
	for _, s := range requiredConfVars {
		viper.Set(s, "dummy-value")
	}
	viper.Set("server.users", "dummy-value")
	assert.NotPanics(t, func() { NewConfig() })
}

func TestInitialization_NoReqsFail(t *testing.T) {
	// Leave one out validation
	for idx := range requiredConfVars {
		viper.Reset()
		for innerIdx, s := range requiredConfVars {
			if idx != innerIdx {
				viper.Set(s, "dummy-value")
			}
		}
		assert.Panics(t, func() { NewConfig() })
	}
}

func TestInitialization_verifyPeerRequiresCerts(t *testing.T) {
	viper.Reset()
	for _, s := range requiredConfVars {
		viper.Set(s, "dummy-value")
	}
	viper.Set("broker.verifyPeer", "true")
	viper.Set("server.jwtpubkeypath", "dummy-value")
	assert.Panics(t, func() { NewConfig() })

	viper.Set("broker.clientCert", "dummy-value")
	viper.Set("broker.clientKey", "dummy-value")
	assert.NotPanics(t, func() { NewConfig() })
}

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
