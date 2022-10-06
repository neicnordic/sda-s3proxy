package main

import (
	"crypto/rand"
	"net/http"
	"os"
	"testing"

	helper "github.com/NBISweden/S3-Upload-Proxy/helper"

	"github.com/minio/minio-go/v6/pkg/s3signer"
	"github.com/stretchr/testify/assert"
)

func TestAlwaysAuthenticator(t *testing.T) {
	a := NewAlwaysAllow()
	r, _ := http.NewRequest("Get", "/", nil)
	_, err := a.Authenticate(r)
	assert.Nil(t, err)
}

func TestUserFileAuthenticator_ReadFile(t *testing.T) {
	a := NewValidateFromFile("dev_utils/users.csv")

	assert := assert.New(t)

	r, err := a.secretFromID("elixirid")
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

func TestUserTokenAuthenticator_ValidateSignature_RSA(t *testing.T) {
	// These tests should be possible to reuse with all correct authenticators somehow

	// Create temp demo rsa key pair
	demoKeysPath := "demo-rsa-keys"
	demoPrKeyName := "/dummy.ega.nbis.se"
	prKeyPath, pubKeyPath, err := helper.MakeFolder(demoKeysPath)
	assert.NoError(t, err)

	err = helper.CreateRSAkeys(prKeyPath, pubKeyPath)
	assert.NoError(t, err)

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	prKeyParsed, err := helper.ParsePrivateRSAKey(prKeyPath, demoPrKeyName)
	assert.NoError(t, err)

	// Create token and set up request defaults
	defaultToken, err := helper.CreateRSAToken(prKeyParsed, "RS256", "JWT", helper.DefaultTokenClaims)
	assert.NoError(t, err)

	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", defaultToken)

	// Test that a user can access their own bucket
	r.URL.Path = "/dummy/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	token, err := a.Authenticate(r)
	assert.Nil(t, err)
	assert.Equal(t, token["pilot"], helper.DefaultTokenClaims["pilot"])

	// Test that a valid user can't access someone elses bucket
	r.URL.Path = "/notvalid/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	_, otherBucket := a.Authenticate(r)
	assert.Equal(t, "token supplied username dummy but URL had notvalid", otherBucket.Error())

	// Create and test Elixir token with wrong username
	wrongUserToken, err := helper.CreateRSAToken(prKeyParsed, "RS256", "JWT", helper.WrongUserClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", wrongUserToken)
	r.URL.Path = "/username/"
	_, wrongUsername := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", wrongUsername.Error())

	// Create and test expired Elixir token
	expiredToken, err := helper.CreateRSAToken(prKeyParsed, "RS256", "JWT", helper.ExpiredClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredToken)
	r.URL.Path = "/dummy/"
	_, err = a.Authenticate(r)
	assert.Nil(t, err)

	// Create and test expired Elixir token with wrong username
	expiredAndWrongUserToken, err := helper.CreateRSAToken(prKeyParsed, "RS256", "JWT", helper.ExpiredAndWrongUserClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredAndWrongUserToken)
	r.URL.Path = "/username/"
	_, expiredAndWrongUser := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", expiredAndWrongUser.Error())

	// Elixir token is not valid (e.g. issued in a future time)
	nonValidToken, err := helper.CreateRSAToken(prKeyParsed, "RS256", "JWT", helper.NonValidClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", nonValidToken)
	r.URL.Path = "/username/"
	_, nonvalidToken := a.Authenticate(r)
	// The error output is huge so a smaller part is compared
	assert.Equal(t, "signed token (RS256) not valid:", nonvalidToken.Error()[0:31])

	// Elixir tokens broken
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", defaultToken[3:])
	r.URL.Path = "/username/"
	_, brokenToken := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken.Error()[0:38])

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "random"+defaultToken)
	r.URL.Path = "/username/"
	_, err = a.Authenticate(r)
	assert.Error(t, err)
	_, brokenToken2 := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken2.Error()[0:38])

	// Delete the keys when testing is done or failed
	defer os.RemoveAll(demoKeysPath)
}

func TestUserTokenAuthenticator_ValidateSignature_EC(t *testing.T) {
	// Create temp demo ec key pair
	demoKeysPath := "demo-ec-keys"
	demoPrKeyName := "/dummy.ega.nbis.se"
	prKeyPath, pubKeyPath, err := helper.MakeFolder(demoKeysPath)
	assert.NoError(t, err)

	err = helper.CreateECkeys(prKeyPath, pubKeyPath)
	assert.NoError(t, err)

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	prKeyParsed, err := helper.ParsePrivateECKey(prKeyPath, demoPrKeyName)
	assert.NoError(t, err)

	// Create token and set up request defaults
	defaultToken, err := helper.CreateECToken(prKeyParsed, "ES256", "JWT", helper.DefaultTokenClaims)
	assert.NoError(t, err)

	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", defaultToken)

	// Test that a user can access their own bucket
	r.URL.Path = "/dummy/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	_, err = a.Authenticate(r)
	assert.Nil(t, err)

	// Test that a valid user can't access someone elses bucket
	r.URL.Path = "/notvalid/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	_, otherBucket := a.Authenticate(r)
	assert.Equal(t, "token supplied username dummy but URL had notvalid", otherBucket.Error())

	// Create and test Elixir token with wrong username
	wrongUserToken, err := helper.CreateECToken(prKeyParsed, "ES256", "JWT", helper.WrongUserClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", wrongUserToken)
	r.URL.Path = "/username/"
	_, wrongUsername := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", wrongUsername.Error())

	// Create and test expired Elixir token
	expiredToken, err := helper.CreateECToken(prKeyParsed, "ES256", "JWT", helper.ExpiredClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredToken)
	r.URL.Path = "/dummy/"
	_, err = a.Authenticate(r)
	assert.Nil(t, err)

	// Create and test expired Elixir token with wrong username
	expiredAndWrongUserToken, err := helper.CreateECToken(prKeyParsed, "ES256", "JWT", helper.ExpiredAndWrongUserClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredAndWrongUserToken)
	r.URL.Path = "/username/"
	_, expiredAndWrongUser := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", expiredAndWrongUser.Error())

	// Elixir token is not valid
	nonValidToken, err := helper.CreateECToken(prKeyParsed, "ES256", "JWT", helper.NonValidClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", nonValidToken)
	r.URL.Path = "/username/"
	_, nonvalidToken := a.Authenticate(r)
	// The error output is huge so a smaller part is compared
	assert.Equal(t, "signed token (ES256) not valid:", nonvalidToken.Error()[0:31])

	// Elixir tokens broken
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", defaultToken[3:])
	r.URL.Path = "/username/"
	_, brokenToken := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken.Error()[0:38])

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "random"+defaultToken)
	r.URL.Path = "/username/"
	_, brokenToken2 := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken2.Error()[0:38])

	defer os.RemoveAll(demoKeysPath)
}

func TestWrongKeyType_RSA(t *testing.T) {
	// Create temp demo ec key pair
	demoKeysPath := "demo-ec-keys"
	demoPrKeyName := "/dummy.ega.nbis.se"
	prKeyPath, pubKeyPath, err := helper.MakeFolder(demoKeysPath)
	assert.NoError(t, err)

	err = helper.CreateECkeys(prKeyPath, pubKeyPath)
	assert.NoError(t, err)

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	_, err = helper.ParsePrivateRSAKey(prKeyPath, demoPrKeyName)
	assert.Equal(t, "x509: failed to parse private key (use ParseECPrivateKey instead for this key format)", err.Error())

	defer os.RemoveAll(demoKeysPath)
}

func TestWrongKeyType_EC(t *testing.T) {
	// Create temp demo ec key pair
	demoKeysPath := "demo-rsa-keys"
	demoPrKeyName := "/dummy.ega.nbis.se"
	prKeyPath, pubKeyPath, err := helper.MakeFolder(demoKeysPath)
	assert.NoError(t, err)

	err = helper.CreateRSAkeys(prKeyPath, pubKeyPath)
	assert.NoError(t, err)

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	_, err = helper.ParsePrivateECKey(prKeyPath, demoPrKeyName)
	assert.Equal(t, "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)", err.Error())

	defer os.RemoveAll(demoKeysPath)
}

func TestUserTokenAuthenticator_ValidateSignature_HS(t *testing.T) {
	// Create random secret
	key := make([]byte, 256)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	// Create HS256 token
	wrongAlgToken, err := helper.CreateHSToken(key, "HS256", "JWT", helper.WrongTokenAlgClaims)
	assert.NoError(t, err)

	testPub := make(map[string][]byte)
	a := NewValidateFromToken(testPub)
	a.pubkeys = make(map[string][]byte)

	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", wrongAlgToken)
	r.URL.Path = "/username/"
	_, WrongAlg := a.Authenticate(r)
	assert.Equal(t, "unsupported algorithm HS256", WrongAlg.Error())
}
