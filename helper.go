package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/dgrijalva/jwt-go"
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

// CreateECkeys creates the RSA key pair
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
