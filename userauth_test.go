package main

import (
	"fmt"
	"net/http"
	"os"
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
	assert.Panics(t, func() { _, _ = a.secretFromID("random") })
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

/*func TestUserTokenAuthenticator_ReadFile(t *testing.T) {
	var pubkeys map[string][]byte
	jwtpubkeypath := "dummy.ega.nbis.se"
	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)

	assert := assert.New(t)

	err := a.getjwtkey("dev_utils/testing-keys/public-key/")
	if assert.Nil(err) {
		assert.Equal(a.pubkeys[jwtpubkeypath], []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 73, 73, 66, 73, 106, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 79, 67, 65, 81, 56, 65, 77, 73, 73, 66, 67, 103, 75, 67, 65, 81, 69, 65, 110, 122, 121, 105, 115, 49, 90, 106, 102, 78, 66, 48, 98, 66, 103, 75, 70, 77, 83, 118, 10, 118, 107, 84, 116, 119, 108, 118, 66, 115, 97, 74, 113, 55, 83, 53, 119, 65, 43, 107, 122, 101, 86, 79, 86, 112, 86, 87, 119, 107, 87, 100, 86, 104, 97, 52, 115, 51, 56, 88, 77, 47, 112, 97, 47, 121, 114, 52, 55, 97, 118, 55, 43, 122, 51, 86, 84, 109, 118, 68, 82, 121, 65, 72, 99, 10, 97, 84, 57, 50, 119, 104, 82, 69, 70, 112, 76, 118, 57, 99, 106, 53, 108, 84, 101, 74, 83, 105, 98, 121, 114, 47, 77, 114, 109, 47, 89, 116, 106, 67, 90, 86, 87, 103, 97, 79, 89, 73, 104, 119, 114, 88, 119, 75, 76, 113, 80, 114, 47, 49, 49, 105, 110, 87, 115, 65, 107, 102, 73, 121, 10, 116, 118, 72, 87, 84, 120, 90, 89, 69, 99, 88, 76, 103, 65, 88, 70, 117, 85, 117, 97, 83, 51, 117, 70, 57, 103, 69, 105, 78, 81, 119, 122, 71, 84, 85, 49, 118, 48, 70, 113, 107, 113, 84, 66, 114, 52, 66, 56, 110, 87, 51, 72, 67, 78, 52, 55, 88, 85, 117, 48, 116, 56, 89, 48, 10, 101, 43, 108, 102, 52, 115, 52, 79, 120, 81, 97, 119, 87, 68, 55, 57, 74, 57, 47, 53, 100, 51, 82, 121, 48, 118, 98, 86, 51, 65, 109, 49, 70, 116, 71, 74, 105, 74, 118, 79, 119, 82, 115, 73, 102, 86, 67, 104, 68, 112, 89, 83, 116, 84, 99, 72, 84, 67, 77, 113, 116, 118, 87, 98, 10, 86, 54, 76, 49, 49, 66, 87, 107, 112, 122, 71, 88, 83, 87, 52, 72, 118, 52, 51, 113, 97, 43, 71, 83, 89, 79, 68, 50, 81, 85, 54, 56, 77, 98, 53, 57, 111, 83, 107, 50, 79, 66, 43, 66, 116, 79, 76, 112, 74, 111, 102, 109, 98, 71, 69, 71, 103, 118, 109, 119, 121, 67, 73, 57, 10, 77, 119, 73, 68, 65, 81, 65, 66, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10})
	}
}*/

func TestUserTokenAuthenticator_NoFile(t *testing.T) {
	var pubkeys map[string][]byte
	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	err := a.getjwtkey("")
	assert.Error(t, err)

	err = a.getjwtpubkey("")
	assert.Error(t, err)
}

func TestUserTokenAuthenticator_WrongURL(t *testing.T) {
	var pubkeys map[string][]byte
	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	jwtpubkeyurl := "/dummy/"

	err := a.getjwtpubkey(jwtpubkeyurl)
	assert.Error(t, err)
}

func TestUserTokenAuthenticator_ValidateSignature(t *testing.T) {
	// These tests should be possible to reuse with all correct authenticators somehow

	// Create temp demo rsa key pair
	demoKeysPath := "demo-rsa-keys"
	demoPrKeyName := "/dummy.ega.nbis.se"
	prKeyPath, pubKeyPath, err := MakeFolder(demoKeysPath)
	if err != nil {
		fmt.Printf("error on creating directory: %v", err)
	}
	err = CreateRSAkeys(prKeyPath, pubKeyPath)
	if err != nil {
		fmt.Printf("error on creating RSA keys: %v", err)
	}

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	prKeyParsed, err := ParsePrivateKey(prKeyPath, demoPrKeyName)
	if err != nil {
		fmt.Printf("error on parsing private key: %v", err)
	}

	// Create token and set up request defaults
	defaultToken, err := CreateToken(prKeyParsed, "RS256", "JWT", defaultTokenClaims)
	if err != nil {
		fmt.Printf("error on creating default token: %v", err)
	}

	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", defaultToken)

	// Test that a user can access their own bucket
	r.URL.Path = "/dummy/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	assert.Nil(t, a.Authenticate(r))

	// Test that a valid user can't access someone elses bucket
	r.URL.Path = "/notvalid/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	otherBucket := a.Authenticate(r)
	assert.Equal(t, "token supplied username dummy but URL had notvalid", otherBucket.Error())

	// Create and test Elixir token with wrong username
	wrongUserToken, err := CreateToken(prKeyParsed, "RS256", "JWT", wrongUserClaims)
	if err != nil {
		fmt.Printf("error on creating wrong user token: %v", err)
	}

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", wrongUserToken)
	r.URL.Path = "/username/"
	wrongUsername := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", wrongUsername.Error())

	// Create and test expired Elixir token
	expiredToken, err := CreateToken(prKeyParsed, "RS256", "JWT", expiredClaims)
	if err != nil {
		fmt.Printf("error on creating expired token: %v", err)
	}

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredToken)
	r.URL.Path = "/dummy/"
	assert.Nil(t, a.Authenticate(r))

	// Create and test expired Elixir token with wrong username
	expiredAndWrongUserToken, err := CreateToken(prKeyParsed, "RS256", "JWT", expiredAndWrongUserClaims)
	if err != nil {
		fmt.Printf("error in creating expired and wrong user token: %v", err)
	}

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredAndWrongUserToken)
	r.URL.Path = "/username/"
	expiredAndWrongUser := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", expiredAndWrongUser.Error())

	// Elixir token is not valid (e.g. issued in a future time)
	nonValidToken, err := CreateToken(prKeyParsed, "RS256", "JWT", nonValidClaims)
	if err != nil {
		fmt.Printf("error on creating non valid token: %v", err)
	}

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", nonValidToken)
	r.URL.Path = "/username/"
	nonvalidToken := a.Authenticate(r)
	// The error output is huge so a smaller part is compared
	assert.Equal(t, "signed token (RS256) not valid:", nonvalidToken.Error()[0:31])

	// Elixir tokens broken
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", defaultToken[3:])
	r.URL.Path = "/username/"
	brokenToken := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken.Error()[0:38])

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "random"+defaultToken)
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))
	brokenToken2 := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken2.Error()[0:38])

	// Delete the keys when testing is done or failed
	defer os.RemoveAll(demoKeysPath)
}
