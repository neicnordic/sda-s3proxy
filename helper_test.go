package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeFolder(t *testing.T) {
	privateK, publicK, _ := MakeFolder("dummy-folder")
	assert.Equal(t, "dummy-folder/private-key", privateK)
	assert.Equal(t, "dummy-folder/public-key", publicK)

	defer os.RemoveAll("dummy-folder")
}

func TestCreateRSAkeys(t *testing.T) {
	privateK, publicK, _ := MakeFolder("dummy-folder")
	assert.Nil(t, CreateRSAkeys(privateK, publicK))

	defer os.RemoveAll("dummy-folder")
}

func TestParsePrivateKey(t *testing.T) {
	privateK, publicK, _ := MakeFolder("dummy-folder")
	CreateRSAkeys(privateK, publicK)
	_, err := ParsePrivateKey(privateK, "/dummy.ega.nbis.se")
	assert.Nil(t, err)

	defer os.RemoveAll("dummy-folder")
}

func TestCreateToken(t *testing.T) {
	privateK, publicK, _ := MakeFolder("dummy-folder")
	CreateRSAkeys(privateK, publicK)
	ParsedPrKey, _ := ParsePrivateKey(privateK, "/dummy.ega.nbis.se")
	_, err := CreateToken(ParsedPrKey, "RS256", "JWT", defaultTokenClaims)
	assert.Nil(t, err)

	defer os.RemoveAll("dummy-folder")
}
