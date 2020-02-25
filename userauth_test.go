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
