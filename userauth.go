package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/minio/minio-go/v6/pkg/s3signer"
	log "github.com/sirupsen/logrus"
)

// Authenticator is an interface that takes care of authenticating users to the
// S3 proxy. It contains only one method, Authenticate.
type Authenticator interface {
	// Authenticate inspects an http.Request and returns nil if the user is
	// authenticated, otherwise an error is returned.
	Authenticate(r *http.Request) error
	CheckJWT(r *http.Request) error
}

// AlwaysAllow is an Authenticator that always authenticates
type AlwaysAllow struct{}

// NewAlwaysAllow returns a new AlwaysAllow authenticator.
func NewAlwaysAllow() *AlwaysAllow {
	return &AlwaysAllow{}
}

// Authenticate authenticates everyone.
func (u *AlwaysAllow) Authenticate(r *http.Request) error {
	return nil
}

// ValidateFromFile is an Authenticator that reads client ids and secret ids
// from a file.
type ValidateFromFile struct {
	filename string
}

// NewValidateFromFile returns a new ValidateFromFile, reading users from the
// supplied file.
func NewValidateFromFile(filename string) *ValidateFromFile {
	return &ValidateFromFile{filename}
}

// Authenticate checks whether the http.Request is signed by any of the users
// in the supplied file.
func (u *ValidateFromFile) Authenticate(r *http.Request) error {
	re := regexp.MustCompile("Credential=([^/]+)/")
	curAccessKey := ""
	if tmp := re.FindStringSubmatch(r.Header.Get("Authorization")); tmp != nil {
		// Check if user requested own bucket
		curAccessKey = tmp[1]
		re := regexp.MustCompile("/([^/]+)/")
		if curAccessKey != re.FindStringSubmatch(r.URL.Path)[1] {
			return fmt.Errorf("user not authorized to access location")
		}
	} else {
		log.Debug("User not found in signature")
		return fmt.Errorf("user not found in signature")
	}

	if curSecretKey, err := u.secretFromID(curAccessKey); err == nil {
		if r.Method == http.MethodGet {
			re := regexp.MustCompile("Signature=(.*)")

			signature := re.FindStringSubmatch(r.Header.Get("Authorization"))
			if signature == nil {
				return fmt.Errorf("user signature not found")
			}

			// Create signing request
			nr, e := http.NewRequest(r.Method, r.URL.String(), r.Body)
			if e != nil {
				fmt.Println(e)
			}

			// Add required headers
			nr.Header.Set("X-Amz-Date", r.Header.Get("X-Amz-Date"))
			nr.Header.Set("X-Amz-Content-Sha256", r.Header.Get("X-Amz-Content-Sha256"))
			nr.Host = r.Host
			nr.URL.RawQuery = r.URL.RawQuery

			// Sign the new request
			s3signer.SignV4(*nr, curAccessKey, curSecretKey, "", "us-east-1")
			curSignature := re.FindStringSubmatch(nr.Header.Get("Authorization"))

			// Compare signatures
			if curSignature[1] != signature[1] {
				return fmt.Errorf("user signature not authenticated")
			}
		}
	} else {
		log.Debug("User not existing: ", curAccessKey)
		return fmt.Errorf("user not existing")
	}
	return nil
}

func (u *ValidateFromFile) secretFromID(id string) (string, error) {
	f, e := os.Open(u.filename)
	if e != nil {
		panic(fmt.Errorf("UsersFileErrMsg: %s", e))
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Debug("Error on close ", err)
		}
	}()

	// TODO: Lookup whether to defer a close here?
	r := csv.NewReader(bufio.NewReader(f))
	for {
		record, e := r.Read()
		if e == io.EOF {
			break
		}
		//log.Debug("Reading user ", record[0])
		if record[0] == id {
			return record[1], nil
		}
	}
	return "", fmt.Errorf("can't find id")
}

func (u *ValidateFromFile) CheckJWT(r *http.Request) error {
	publicKeyPath := "/Users/dimitris/Testing/jwt/pub.rsa"

	tokenStr := r.Header.Get("X-Amz-Security-Token")
	isValid, err := verifyToken(tokenStr, publicKeyPath)
	if err != nil || !isValid {
		fmt.Println(err)
		return fmt.Errorf("user token not valid")
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) { return nil, nil })
	re := regexp.MustCompile("/([^/]+)/")
	username := re.FindStringSubmatch(r.URL.Path)[1]
	fmt.Println(username)
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if claims["sub"] != username {
			return fmt.Errorf("user token not valid")
		}
	}

	return nil
}

func verifyToken(token, publicKeyPath string) (bool, error) {
	keyData, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return false, err
	}
	key, err := jwt.ParseECPublicKeyFromPEM(keyData)
	if err != nil {
		return false, err
	}

	parts := strings.Split(token, ".")
	err = jwt.SigningMethodES256.Verify(strings.Join(parts[0:2], "."), parts[2], key)
	if err != nil {
		return false, err
	}
	return true, nil
}

