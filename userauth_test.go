package main

import (
	"net/http"
	"testing"

	"github.com/minio/minio-go/v6/pkg/s3signer"
	"github.com/stretchr/testify/assert"
)

func TestAlwaysAuthenticator(t *testing.T) {
	a := NewAlwaysAllow()
	r, _ := http.NewRequest("Get", "/", nil)
	assert.Nil(t, a.Authenticate(r))
}

func TestUserFileAuthenticator_ReadFile(t *testing.T) {
	a := NewValidateFromFile("dev_utils/users.csv")

	assert := assert.New(t)

	r, err := a.secretFromID("elexirid")
	if assert.Nil(err) {
		assert.Equal(r, "987654321")
	}
	r, err = a.secretFromID("anotherid")
	if assert.Nil(err) {
		assert.Equal(r, "testpass")
	}
	r, err = a.secretFromID("username")
	if assert.Nil(err) {
		assert.Equal(r, "testpass")
	}

	_, err = a.secretFromID("nonexistentuser")
	assert.NotNil(err)
}

func TestUserFileAuthenticator_NoFile(t *testing.T) {
	a := NewValidateFromFile("1298379somerandomfilenamethatwedonthaveinthefilesystem1928739")
	assert.Panics(t, func() { a.secretFromID("random") })
}

func TestUserFileAuthenticator_ValidateSignature(t *testing.T) {
	// These tests should be possible to reuse with all correct authenticators somehow
	a := NewValidateFromFile("dev_utils/users.csv")

	// Set up request defaults
	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Content-Sha256", "Just needs to be here")

	// Test that a user can access their own bucket
	r.URL.Path = "/username/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	assert.Nil(t, a.Authenticate(r))

	// Test that a valid user can't access someone elses bucket
	r.URL.Path = "/notvalid/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	assert.Error(t, a.Authenticate(r))

	// Test that incorrect secret don't validate
	r.URL.Path = "/username/"
	s3signer.SignV4(*r, "username", "incorrect", "", "us-east-1")
	assert.Error(t, a.Authenticate(r))

	// Test that nonexistant user can't log in
	r.URL.Path = "/snubbe/"
	s3signer.SignV4(*r, "snubbe", "incorrect", "", "us-east-1")
	assert.Error(t, a.Authenticate(r))

	// Test that nonexistant user can't log in to other bucket
	r.URL.Path = "/username/"
	s3signer.SignV4(*r, "snubbe", "incorrect", "", "us-east-1")
	assert.Error(t, a.Authenticate(r))

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Content-Sha256", "Just needs to be here")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))
}

func TestUserTokenAuthenticator_ReadFile(t *testing.T) {
	var pubkeys map[string][]byte
	jwtpubkeypath := "dummy.ega.nbis.se"
	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)

	assert := assert.New(t)

	err := a.getjwtKey("dev_utils/keys/")
	if assert.Nil(err) {
		assert.Equal(a.pubkeys[jwtpubkeypath], []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 47, 107, 101, 116, 116, 69, 72, 84, 50, 112, 112, 73, 75, 49, 70, 101, 54, 89, 65, 69, 66, 85, 70, 119, 53, 114, 103, 50, 10, 87, 101, 108, 51, 79, 80, 78, 55, 56, 106, 69, 48, 98, 89, 105, 111, 90, 57, 78, 71, 107, 55, 111, 79, 100, 111, 114, 55, 78, 43, 76, 108, 100, 87, 73, 85, 49, 89, 66, 120, 102, 68, 65, 119, 112, 116, 49, 81, 117, 112, 71, 47, 70, 78, 110, 89, 100, 103, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10})
	}
}

func TestUserTokenAuthenticator_NoFile(t *testing.T) {
	var pubkeys map[string][]byte
	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	err := a.getjwtKey("")
	assert.Error(t, err)

	err = a.getjwtpubkey("")
	assert.Error(t, err)
}

func TestUserTokenAuthenticator_ValidateSignature(t *testing.T) {
	// These tests should be possible to reuse with all correct authenticators somehow
	var pubkeys map[string][]byte
	jwtpubkeypath := "dev_utils/keys/"
	//elkeyurl := "https://login.elixir-czech.org/oidc/jwk"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	a.getjwtKey(jwtpubkeypath)

	// Set up request defaults
	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkdW1teS5lZ2EubmJpcy5zZSIsInN1YiI6ImR1bW15In0.W0G7myQTxYRjRbFFw_WHAbYkNr6RQxf3MCYKNw-iv3HgMiBfXexcaMFk_CZPvXmlJqZ-Aav7dIHI_-zEhINJIQ")

	// Test that a user can access their own bucket
	r.URL.Path = "/dummy/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	assert.Nil(t, a.Authenticate(r))

	// Test that a valid user can't access someone elses bucket
	r.URL.Path = "/notvalid/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	assert.Error(t, a.Authenticate(r))

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkdW1teS5lZ2EubmJpcy5zZSIsInN1YiI6ImR1bW15In0.W0G7myQTxYRjRbFFw_WHAbYkNr6RQxf3MCYKNw-iv3HgMiBfXexcaMFk_CZPvXmlJqZ-Aav7dIHI_-zEhINJIQ")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))
}
