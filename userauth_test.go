package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/minio/minio-go/v6/pkg/s3signer"
	"github.com/stretchr/testify/assert"
)

// Global variables for test token creation

var (
	defaultTokenClaims = map[string]interface{}{
		"iss": "https://dummy.ega.nbis.se",
		"sub": "dummy",
		"exp": time.Now().Add(time.Hour * 2).Unix(),
	}

	wrongUserClaims = map[string]interface{}{
		"sub":   "c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org",
		"aud":   "15137645-3153-4d49-9ddb-594027cd4ca7",
		"azp":   "15137645-3153-4d49-9ddb-594027cd4ca7",
		"scope": "ga4gh_passport_v1 openid",
		"iss":   "https://dummy.ega.nbis.se",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour * 2).Unix(),
		"jti":   "5e6c6d24-42eb-408e-ba20-203904e388a1",
	}

	expiredClaims = map[string]interface{}{
		"sub":   "dummy",
		"aud":   "15137645-3153-4d49-9ddb-594027cd4ca7",
		"azp":   "15137645-3153-4d49-9ddb-594027cd4ca7",
		"scope": "ga4gh_passport_v1 openid",
		"iss":   "https://dummy.ega.nbis.se",
		"exp":   time.Now().Add(-time.Hour * 2).Unix(),
		"iat":   time.Now().Unix(),
		"jti":   "5e6c6d24-42eb-408e-ba20-203904e388a1",
	}

	expiredAndWrongUserClaims = map[string]interface{}{
		"sub":   "c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org",
		"aud":   "15137645-3153-4d49-9ddb-594027cd4ca7",
		"azp":   "15137645-3153-4d49-9ddb-594027cd4ca7",
		"scope": "ga4gh_passport_v1 openid",
		"iss":   "https://dummy.ega.nbis.se",
		"exp":   time.Now().Add(-time.Hour * 2).Unix(),
		"iat":   time.Now().Unix(),
		"jti":   "5e6c6d24-42eb-408e-ba20-203904e388a1",
	}

	nonValidClaims = map[string]interface{}{
		"sub":   "c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org",
		"aud":   "15137645-3153-4d49-9ddb-594027cd4ca7",
		"azp":   "15137645-3153-4d49-9ddb-594027cd4ca7",
		"scope": "ga4gh_passport_v1 openid",
		"iss":   "https://dummy.ega.nbis.se",
		"exp":   time.Now().Add(time.Hour * 2).Unix(),
		"iat":   time.Now().Add(time.Hour * 2).Unix(),
		"jti":   "5e6c6d24-42eb-408e-ba20-203904e388a1",
	}

	wrongTokenAlgClaims = map[string]interface{}{
		"iss":       "Online JWT Builder",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour * 2).Unix(),
		"aud":       "4e9416a7-3515-447a-b848-d4ac7a57f",
		"sub":       "pleasefix@snurre-in-the-house.org",
		"auth_time": "1632207224",
		"jti":       "cc847f9c-7608-4b4f-9c6f-6e734813355f",
	}
)

// MakeFolder creates a folder and subfolders for the keys pair
// Returns the two paths
func MakeFolder(path string) (string, string, error) {
	prKeyPath := path + "/private-key"
	pubKeyPath := path + "/public-key"
	err := os.MkdirAll(prKeyPath, 0750)
	if err != nil {
		//fmt.Errorf("error creating directory: %v", err)
		return "no path", "no path", err
	}
	err = os.MkdirAll(pubKeyPath, 0750)
	if err != nil {
		//fmt.Errorf("error creatin directory: %w", err)
		return "no path", "no path", err
	}

	return prKeyPath, pubKeyPath, nil
}

// ParsePrivateRSAKey reads and parses the RSA private key
func ParsePrivateRSAKey(path, keyName string) (*rsa.PrivateKey, error) {
	keyPath := path + keyName
	prKey, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}

	prKeyParsed, err := jwt.ParseRSAPrivateKeyFromPEM(prKey)
	if err != nil {
		return nil, err
	}

	return prKeyParsed, nil
}

// CreateRSAkeys creates the RSA key pair
func CreateRSAkeys(prPath, pubPath string) error {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create(prPath + "/dummy.ega.nbis.se")
	if err != nil {
		return err
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return err
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(pubPath + "/dummy.ega.nbis.se.pub")
	if err != nil {
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return err
	}

	return nil
}

// CreateRSAToken creates an RSA token
func CreateRSAToken(key *rsa.PrivateKey, headerAlg, headerType string, tokenClaims map[string]interface{}) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["alg"] = headerAlg
	token.Header["typ"] = headerType
	claims := make(jwt.MapClaims)
	for key, value := range tokenClaims {
		claims[key] = value
	}
	token.Claims = claims
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "no-token", err
	}

	return tokenString, nil
}

// CreateECToken creates an EC token
func CreateECToken(key *ecdsa.PrivateKey, headerAlg, headerType string, tokenClaims map[string]interface{}) (string, error) {
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["alg"] = headerAlg
	token.Header["typ"] = headerType
	claims := make(jwt.MapClaims)
	for key, value := range tokenClaims {
		claims[key] = value
	}
	token.Claims = claims
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "no-token", err
	}

	return tokenString, nil
}

// CreateHSToken creates an HS token
func CreateHSToken(key []byte, headerAlg, headerType string, tokenClaims map[string]interface{}) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Header["alg"] = headerAlg
	token.Header["typ"] = headerType
	claims := make(jwt.MapClaims)
	for key, value := range tokenClaims {
		claims[key] = value
	}
	token.Claims = claims
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "no-token", err
	}

	return tokenString, nil
}

// ParsePrivateECKey reads and parses the EC private key
func ParsePrivateECKey(path, keyName string) (*ecdsa.PrivateKey, error) {
	keyPath := path + keyName
	prKey, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}

	prKeyParsed, err := jwt.ParseECPrivateKeyFromPEM(prKey)
	if err != nil {
		return nil, err
	}

	return prKeyParsed, nil
}

// CreateECkeys creates the EC key pair
func CreateECkeys(prPath, pubPath string) error {
	privatekey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	privateKeyBytes, _ := x509.MarshalECPrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create(prPath + "/dummy.ega.nbis.se")
	if err != nil {
		return err
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return err
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(pubPath + "/dummy.ega.nbis.se.pub")
	if err != nil {
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return err
	}

	return nil
}

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
	prKeyPath, pubKeyPath, err := MakeFolder(demoKeysPath)
	assert.NoError(t, err)

	err = CreateRSAkeys(prKeyPath, pubKeyPath)
	assert.NoError(t, err)

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	prKeyParsed, err := ParsePrivateRSAKey(prKeyPath, demoPrKeyName)
	assert.NoError(t, err)

	// Create token and set up request defaults
	defaultToken, err := CreateRSAToken(prKeyParsed, "RS256", "JWT", defaultTokenClaims)
	assert.NoError(t, err)

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
	wrongUserToken, err := CreateRSAToken(prKeyParsed, "RS256", "JWT", wrongUserClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", wrongUserToken)
	r.URL.Path = "/username/"
	wrongUsername := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", wrongUsername.Error())

	// Create and test expired Elixir token
	expiredToken, err := CreateRSAToken(prKeyParsed, "RS256", "JWT", expiredClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredToken)
	r.URL.Path = "/dummy/"
	assert.Nil(t, a.Authenticate(r))

	// Create and test expired Elixir token with wrong username
	expiredAndWrongUserToken, err := CreateRSAToken(prKeyParsed, "RS256", "JWT", expiredAndWrongUserClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredAndWrongUserToken)
	r.URL.Path = "/username/"
	expiredAndWrongUser := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", expiredAndWrongUser.Error())

	// Elixir token is not valid (e.g. issued in a future time)
	nonValidToken, err := CreateRSAToken(prKeyParsed, "RS256", "JWT", nonValidClaims)
	assert.NoError(t, err)

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

func TestUserTokenAuthenticator_ValidateSignature_EC(t *testing.T) {
	// Create temp demo ec key pair
	demoKeysPath := "demo-ec-keys"
	demoPrKeyName := "/dummy.ega.nbis.se"
	prKeyPath, pubKeyPath, err := MakeFolder(demoKeysPath)
	assert.NoError(t, err)

	err = CreateECkeys(prKeyPath, pubKeyPath)
	assert.NoError(t, err)

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	prKeyParsed, err := ParsePrivateECKey(prKeyPath, demoPrKeyName)
	assert.NoError(t, err)

	// Create token and set up request defaults
	defaultToken, err := CreateECToken(prKeyParsed, "ES256", "JWT", defaultTokenClaims)
	assert.NoError(t, err)

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
	wrongUserToken, err := CreateECToken(prKeyParsed, "ES256", "JWT", wrongUserClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", wrongUserToken)
	r.URL.Path = "/username/"
	wrongUsername := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", wrongUsername.Error())

	// Create and test expired Elixir token
	expiredToken, err := CreateECToken(prKeyParsed, "ES256", "JWT", expiredClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredToken)
	r.URL.Path = "/dummy/"
	assert.Nil(t, a.Authenticate(r))

	// Create and test expired Elixir token with wrong username
	expiredAndWrongUserToken, err := CreateECToken(prKeyParsed, "ES256", "JWT", expiredAndWrongUserClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", expiredAndWrongUserToken)
	r.URL.Path = "/username/"
	expiredAndWrongUser := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", expiredAndWrongUser.Error())

	// Elixir token is not valid
	nonValidToken, err := CreateECToken(prKeyParsed, "ES256", "JWT", nonValidClaims)
	assert.NoError(t, err)

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", nonValidToken)
	r.URL.Path = "/username/"
	nonvalidToken := a.Authenticate(r)
	// The error output is huge so a smaller part is compared
	assert.Equal(t, "signed token (ES256) not valid:", nonvalidToken.Error()[0:31])

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
	brokenToken2 := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken2.Error()[0:38])

	defer os.RemoveAll(demoKeysPath)
}

func TestWrongKeyType_RSA(t *testing.T) {
	// Create temp demo ec key pair
	demoKeysPath := "demo-ec-keys"
	demoPrKeyName := "/dummy.ega.nbis.se"
	prKeyPath, pubKeyPath, err := MakeFolder(demoKeysPath)
	assert.NoError(t, err)

	err = CreateECkeys(prKeyPath, pubKeyPath)
	assert.NoError(t, err)

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	_, err = ParsePrivateRSAKey(prKeyPath, demoPrKeyName)
	assert.Equal(t, "x509: failed to parse private key (use ParseECPrivateKey instead for this key format)", err.Error())

	defer os.RemoveAll(demoKeysPath)
}

func TestWrongKeyType_EC(t *testing.T) {
	// Create temp demo ec key pair
	demoKeysPath := "demo-rsa-keys"
	demoPrKeyName := "/dummy.ega.nbis.se"
	prKeyPath, pubKeyPath, err := MakeFolder(demoKeysPath)
	assert.NoError(t, err)

	err = CreateRSAkeys(prKeyPath, pubKeyPath)
	assert.NoError(t, err)

	var pubkeys map[string][]byte
	jwtpubkeypath := demoKeysPath + "/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Parse demo private key
	_, err = ParsePrivateECKey(prKeyPath, demoPrKeyName)
	assert.Equal(t, "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)", err.Error())

	defer os.RemoveAll(demoKeysPath)
}

func TestUserTokenAuthenticator_ValidateSignature_HS(t *testing.T) {
	//Create random secret
	key := make([]byte, 256)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	// Create HS256 token
	wrongAlgToken, err := CreateHSToken(key, "HS256", "JWT", wrongTokenAlgClaims)
	assert.NoError(t, err)

	testPub := make(map[string][]byte)
	a := NewValidateFromToken(testPub)
	a.pubkeys = make(map[string][]byte)

	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", wrongAlgToken)
	r.URL.Path = "/username/"
	WrongAlg := a.Authenticate(r)
	assert.Equal(t, "unsupported algorithm HS256", WrongAlg.Error())
}
