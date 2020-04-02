package main

import (
	"bufio"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/minio/minio-go/v6/pkg/s3signer"
	log "github.com/sirupsen/logrus"
)

// Authenticator is an interface that takes care of authenticating users to the
// S3 proxy. It contains only one method, Authenticate.
type Authenticator interface {
	// Authenticate inspects an http.Request and returns nil if the user is
	// authenticated, otherwise an error is returned.
	Authenticate(r *http.Request) error
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

// ValidateFromToken is an Authenticator that reads the public key from
// supplied file
type ValidateFromToken struct {
	pubkeys map[string][]byte
}

// NewValidateFromToken returns a new ValidateFromToken, reading the key from
// the supplied file.
func NewValidateFromToken(pubkeys map[string][]byte) *ValidateFromToken {
	return &ValidateFromToken{pubkeys}
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

// Authenticate verifies that the token included in the http.Request
// is valid
func (u *ValidateFromToken) Authenticate(r *http.Request) error {
	// Verify signature by parsing the token with the given key
	tokenStr := r.Header.Get("X-Amz-Security-Token")
	if tokenStr == "" {
		return fmt.Errorf("user token not found")
	}
	token, _ := jwt.Parse(tokenStr, func(tokenStr *jwt.Token) (interface{}, error) { return nil, nil })
	if token.Header["alg"] == "ES256" {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			strIss := fmt.Sprintf("%v", claims["iss"])
			key, err := jwt.ParseECPublicKeyFromPEM(u.pubkeys[strIss])
			if err != nil {
				return fmt.Errorf("failed to parse public key")
			}
			_, err = jwt.Parse(tokenStr, func(tokenStr *jwt.Token) (interface{}, error) { return key, nil })
			if err != nil {
				return fmt.Errorf("user token not valid")
			}
		}
	} else if token.Header["alg"] == "RS256" {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			strIss := fmt.Sprintf("%v", claims["iss"])
			re := regexp.MustCompile(`//([^/]*)/`)
			key, err := jwt.ParseRSAPublicKeyFromPEM(u.pubkeys[re.FindStringSubmatch(strIss)[1]])
			if err != nil {
				return fmt.Errorf("failed to parse public key")
			}
			_, err = jwt.Parse(tokenStr, func(tokenStr *jwt.Token) (interface{}, error) { return key, nil })
			if err != nil {
				return fmt.Errorf("user token not valid")
			}
		}
	}
	// Check whether token username and filepath match
	re := regexp.MustCompile("/([^/]+)/")
	username := re.FindStringSubmatch(r.URL.Path)[1]
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if claims["sub"] != username {
			return fmt.Errorf("token username different that url")
		}
	}
	return nil
}

// Function for reading the ega key in []byte
func (u *ValidateFromToken) getjwtKey(jwtpubkeypath string) error {
	files, err := ioutil.ReadDir(jwtpubkeypath)
	if err != nil {
		return fmt.Errorf("failed to get public key files")
	}
	re := regexp.MustCompile(`(.*)\.+`)
	for _, file := range files {
		keyData, err := ioutil.ReadFile(filepath.Join(filepath.Clean(jwtpubkeypath), file.Name()))
		if err != nil {
			return fmt.Errorf("token file error")
		}
		mapkey := re.FindStringSubmatch(file.Name())[1]
		u.pubkeys[mapkey] = keyData

	}
	return nil
}

// Function for fetching the elixir key from the JWK and transform it to []byte
func (u *ValidateFromToken) getjwtpubkey(jwtpubkeyurl string) error {
	re := regexp.MustCompile("/([^/]+)/")
	if re.FindStringSubmatch(jwtpubkeyurl) == nil {
		return fmt.Errorf("not valid link")
	}
	key := re.FindStringSubmatch(jwtpubkeyurl)[1]
	set, err := jwk.Fetch(jwtpubkeyurl)
	if err != nil {
		return fmt.Errorf("failed to parse JWK")
	}
	keyEl, err := set.Keys[0].Materialize()
	if err != nil {
		return fmt.Errorf("failed to generate public key")
	}
	pkeyBytes, err := x509.MarshalPKIXPublicKey(keyEl)
	if err != nil {
		return fmt.Errorf("failed to marshal public key")
	}

	r, err := http.Get(jwtpubkeyurl)
	if err != nil {
		return fmt.Errorf("failed to get JWK")
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to parse response")
	}
	defer r.Body.Close()
	var keytype map[string][]map[string]string
	err = json.Unmarshal(b, &keytype)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response")
	}
	keyData := pem.EncodeToMemory(
		&pem.Block{
			Type:  keytype["keys"][0]["kty"] + " PUBLIC KEY",
			Bytes: pkeyBytes,
		},
	)
	u.pubkeys[key] = keyData
	return nil
}
