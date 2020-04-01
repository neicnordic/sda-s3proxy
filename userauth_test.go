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
	jwtpubkeyurl := "https://login.elixir-czech.org/oidc/jwk"
	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)

	assert := assert.New(t)

	err := a.getjwtKey("dev_utils/keys/")
	if assert.Nil(err) {
		assert.Equal(a.pubkeys[jwtpubkeypath], []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 47, 107, 101, 116, 116, 69, 72, 84, 50, 112, 112, 73, 75, 49, 70, 101, 54, 89, 65, 69, 66, 85, 70, 119, 53, 114, 103, 50, 10, 87, 101, 108, 51, 79, 80, 78, 55, 56, 106, 69, 48, 98, 89, 105, 111, 90, 57, 78, 71, 107, 55, 111, 79, 100, 111, 114, 55, 78, 43, 76, 108, 100, 87, 73, 85, 49, 89, 66, 120, 102, 68, 65, 119, 112, 116, 49, 81, 117, 112, 71, 47, 70, 78, 110, 89, 100, 103, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10})
	}

	err = a.getjwtpubkey(jwtpubkeyurl)
	if assert.Nil(err) {
		assert.Equal(a.pubkeys["login.elixir-czech.org"], []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 82, 83, 65, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 73, 73, 66, 73, 106, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 79, 67, 65, 81, 56, 65, 77, 73, 73, 66, 67, 103, 75, 67, 65, 81, 69, 65, 117, 86, 72, 80, 102, 85, 72, 86, 69, 122, 112, 103, 79, 110, 68, 78, 105, 51, 101, 50, 10, 112, 86, 115, 98, 75, 49, 104, 115, 73, 78, 115, 84, 121, 47, 49, 109, 77, 84, 55, 115, 120, 68, 121, 80, 43, 49, 101, 81, 83, 106, 122, 89, 115, 71, 83, 85, 74, 51, 71, 72, 113, 57, 76, 104, 105, 86, 110, 100, 112, 119, 86, 56, 121, 55, 69, 110, 106, 100, 106, 48, 112, 117, 114, 121, 10, 119, 116, 119, 107, 47, 68, 56, 122, 57, 73, 73, 78, 51, 54, 82, 74, 65, 104, 49, 121, 104, 70, 102, 98, 121, 104, 76, 80, 69, 90, 108, 67, 68, 100, 122, 120, 97, 115, 53, 68, 107, 117, 57, 107, 48, 71, 114, 120, 81, 117, 86, 54, 105, 51, 48, 77, 105, 100, 56, 79, 103, 82, 81, 50, 10, 113, 51, 112, 109, 115, 107, 115, 52, 49, 52, 65, 102, 121, 54, 120, 117, 103, 67, 54, 117, 51, 105, 110, 121, 106, 76, 122, 76, 80, 114, 104, 82, 48, 111, 82, 80, 84, 71, 100, 78, 77, 88, 74, 98, 71, 119, 52, 115, 86, 84, 106, 110, 104, 53, 65, 122, 84, 103, 88, 43, 71, 114, 81, 87, 10, 66, 72, 83, 106, 73, 55, 114, 77, 84, 99, 118, 113, 98, 98, 108, 55, 77, 56, 79, 79, 104, 69, 51, 77, 81, 47, 103, 102, 86, 76, 88, 119, 109, 119, 83, 73, 111, 75, 72, 79, 68, 67, 48, 82, 79, 43, 88, 110, 86, 104, 113, 100, 55, 81, 102, 48, 116, 101, 83, 49, 74, 105, 73, 76, 10, 75, 89, 76, 108, 53, 70, 83, 47, 55, 85, 121, 50, 67, 108, 86, 114, 65, 89, 100, 50, 84, 54, 88, 57, 68, 73, 114, 47, 74, 108, 112, 82, 107, 119, 83, 68, 56, 57, 57, 112, 113, 54, 80, 82, 57, 110, 104, 75, 103, 117, 105, 112, 74, 69, 48, 113, 85, 88, 120, 97, 109, 100, 89, 57, 10, 110, 119, 73, 68, 65, 81, 65, 66, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 82, 83, 65, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10})
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
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb2dpbi5lZ2EubmJpcy5zZSIsInN1YiI6ImR1bW15In0.SyZ9nZ4K9Y-fj-S37p3akwrlO6wJCLE7zXIvoTJhGxWJwHUGk-sIQLSj6K1WYjjatgGmQXF3mvmZYYLY1nkKwA")

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
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb2dpbi5lZ2EubmJpcy5zZSIsInN1YiI6ImR1bW15In0.SyZ9nZ4K9Y-fj-S37p3akwrlO6wJCLE7zXIvoTJhGxWJwHUGk-sIQLSj6K1WYjjatgGmQXF3mvmZYYLY1nkKwA")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))
}
