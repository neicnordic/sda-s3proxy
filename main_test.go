package main

import (
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestInitialization_NoConfig(t *testing.T) {
	fmt.Println("Test init no config")
	viper.Reset()
	assert.Panics(t, func() { initialization() })
}

func TestInitialization_confPath(t *testing.T) {
	fmt.Println("Test init conf path")
	viper.Reset()
	viper.Set("server.confPath", "dev_utils/")
	assert.NotPanics(t, func() { initialization() })
}

func TestInitialization_WrongConfFile(t *testing.T) {
	fmt.Println("Test init wrong config file")
	viper.Reset()
	viper.SetConfigType("")
	viper.Set("server.confFile", "dev_utils/certs/ca.crt")
	assert.Panics(t, func() { initialization() })
}

func TestInitialization_ConfFile(t *testing.T) {
	fmt.Println("Test init")
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")
	assert.NotPanics(t, func() { initialization() })
}

func TestInitialization_NoCaCerts(t *testing.T) {
	fmt.Println("Test init no CaCerts")
	viper.Reset()
	viper.Set("server.confFile", "dev_utils/config.yaml")
	SystemCAs = x509.NewCertPool()
	initialization()
}
