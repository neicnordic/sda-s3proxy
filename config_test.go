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

// what does this test test?
/*
func TestInitialization_NoCaCerts(t *testing.T) {
	fmt.Println("Test init no CaCerts")
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")
	SystemCAs = x509.NewCertPool()
	NewConfig()
}
*/
