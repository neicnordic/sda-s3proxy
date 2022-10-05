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
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/minio/minio-go/v6/pkg/s3signer"
	log "github.com/sirupsen/logrus"
)

// Authenticator is an interface that takes care of authenticating users to the
// S3 proxy. It contains only one method, Authenticate.
type Authenticator interface {
	// Authenticate inspects an http.Request and returns nil if the user is
	// authenticated, otherwise an error is returned.
	Authenticate(r *http.Request) (jwt.MapClaims, error)
}

// AlwaysAllow is an Authenticator that always authenticates
type AlwaysAllow struct{}

// NewAlwaysAllow returns a new AlwaysAllow authenticator.
func NewAlwaysAllow() *AlwaysAllow {
	return &AlwaysAllow{}
}

// Authenticate authenticates everyone.
func (u *AlwaysAllow) Authenticate(r *http.Request) (jwt.MapClaims, error) {
	return nil, nil
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
	auth := r.Header.Get("Authorization")
	curAccessKey := ""
	if tmp := re.FindStringSubmatch(auth); tmp != nil {
		// Check if user requested own bucket
		curAccessKey = tmp[1]
		re := regexp.MustCompile("/([^/]+)/")
		if curAccessKey != re.FindStringSubmatch(r.URL.Path)[1] {
			return fmt.Errorf("user not authorized to access location")
		}
	} else {
		log.Debugf("No credentials in Authorization header (%s)", auth)
		return fmt.Errorf("authorization header had no credentials")
	}
	//nolint:nestif
	if curSecretKey, err := u.secretFromID(curAccessKey); err == nil {
		if r.Method == http.MethodGet {
			re := regexp.MustCompile("Signature=(.*)")

			signature := re.FindStringSubmatch(auth)
			if signature == nil || len(signature) < 2 {
				return fmt.Errorf("signature not found in Authorization header (%s)", auth)
			}

			// Create signing request
			nr, e := http.NewRequest(r.Method, r.URL.String(), r.Body)
			if e != nil {
				log.Debug("error creating the new request")
				log.Debug(e)
			}

			// Add required headers
			nr.Header.Set("X-Amz-Date", r.Header.Get("X-Amz-Date"))
			nr.Header.Set("X-Amz-Content-Sha256", r.Header.Get("X-Amz-Content-Sha256"))
			nr.Host = r.Host
			nr.URL.RawQuery = r.URL.RawQuery

			// Sign the new request
			s3signer.SignV4(*nr, curAccessKey, curSecretKey, "", "us-east-1")
			curSignature := re.FindStringSubmatch(nr.Header.Get("Authorization"))

			if curSignature == nil || len(signature) < 2 {
				return fmt.Errorf("generated outgoing signature not found or unexpected (header wass %s)",
					nr.Header.Get("Authorization"))
			}

			// Compare signatures
			if curSignature[1] != signature[1] {
				return fmt.Errorf("signature for outgoing (%s)request does not match incoming (%s",
					curSignature[1], signature[1])
			}
		}
	} else {
		log.Debugf("Found no secret for user %s", curAccessKey)
		return fmt.Errorf("no secret for user %s found", curAccessKey)
	}
	return nil
}

func (u *ValidateFromFile) secretFromID(id string) (string, error) {
	f, e := os.Open(u.filename)
	if e != nil {
		log.Panicf("Error opening users file (%s): %v",
			u.filename,
			e)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Debugf("Error on close: %v", err)
		}
	}()

	r := csv.NewReader(bufio.NewReader(f))
	for {
		record, e := r.Read()
		if e == io.EOF {
			break
		}
		if record[0] == id {
			log.Debugf("Returning secret for id %s", id)
			return record[1], nil
		}
	}

	log.Debugf("No secret found for id %s in %s", id, u.filename)
	return "", fmt.Errorf("cannot find id %s in %s", id, u.filename)
}

// Authenticate verifies that the token included in the http.Request
// is valid
func (u *ValidateFromToken) Authenticate(r *http.Request) (claims jwt.MapClaims, err error) {
	var ok bool

	// Verify signature by parsing the token with the given key
	tokenStr := r.Header.Get("X-Amz-Security-Token")
	if tokenStr == "" {
		return nil, fmt.Errorf("no access token supplied")
	}

	token, err := jwt.Parse(tokenStr, func(tokenStr *jwt.Token) (interface{}, error) { return nil, nil })
	// Return error if token is broken (without claims)
	if claims, ok = token.Claims.(jwt.MapClaims); !ok {
		return nil, fmt.Errorf("broken token (claims are empty): %v\nerror: %s", claims, err)
	}
	//nolint:nestif
	if claims, ok = token.Claims.(jwt.MapClaims); ok {
		strIss := fmt.Sprintf("%v", claims["iss"])
		// Poor string unescaper for elixir
		strIss = strings.ReplaceAll(strIss, "\\", "")

		log.Debugf("Looking for key for %s", strIss)

		re := regexp.MustCompile(`//([^/]*)`)
		if token.Header["alg"] == "ES256" {
			key, err := jwt.ParseECPublicKeyFromPEM(u.pubkeys[re.FindStringSubmatch(strIss)[1]])
			if err != nil {
				return nil, fmt.Errorf("failed to parse EC public key (%v)", err)
			}
			_, err = jwt.Parse(tokenStr, func(tokenStr *jwt.Token) (interface{}, error) { return key, nil })
			// Validate the error
			v, _ := err.(*jwt.ValidationError)
			// If error is for expired token continue
			if err != nil && v.Errors != jwt.ValidationErrorExpired {
				return nil, fmt.Errorf("signed token (ES256) not valid: %v, (token was %s)", err, tokenStr)
			}
		} else if token.Header["alg"] == "RS256" {
			key, err := jwt.ParseRSAPublicKeyFromPEM(u.pubkeys[re.FindStringSubmatch(strIss)[1]])
			if err != nil {
				return nil, fmt.Errorf("failed to parse RSA256 public key (%v)", err)
			}
			_, err = jwt.Parse(tokenStr, func(tokenStr *jwt.Token) (interface{}, error) { return key, nil })
			// Validate the error
			v, _ := err.(*jwt.ValidationError)
			// If error is for expired token continue
			if err != nil && v.Errors != jwt.ValidationErrorExpired {
				return nil, fmt.Errorf("signed token (RS256) not valid: %v, (token was %s)", err, tokenStr)
			}
		} else {
			return nil, fmt.Errorf("unsupported algorithm %s", token.Header["alg"])
		}
	}
	// Check whether token username and filepath match
	re := regexp.MustCompile("/([^/]+)/")
	username := re.FindStringSubmatch(r.URL.Path)[1]
	//nolint:nestif
	if claims, ok = token.Claims.(jwt.MapClaims); ok {
		// Case for Elixir usernames - Remove everything after @ character
		if strings.Contains(fmt.Sprintf("%v", claims["sub"]), "@") {
			claimString := fmt.Sprintf("%v", claims["sub"])
			if claimString[:strings.Index(claimString, "@")] != username {
				return nil, fmt.Errorf("token supplied username %s but URL had %s",
					claims["sub"], username)
			}
		} else {
			if claims["sub"] != username {
				return nil, fmt.Errorf("token supplied username %s but URL had %s",
					claims["sub"], username)
			}
		}
	}

	return claims, nil
}

// Function for reading the ega key in []byte
func (u *ValidateFromToken) getjwtkey(jwtpubkeypath string) error {
	re := regexp.MustCompile(`(.*)\.+`)
	err := filepath.Walk(jwtpubkeypath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				log.Debug("Reading file: ", filepath.Join(filepath.Clean(jwtpubkeypath), info.Name()))
				keyData, err := ioutil.ReadFile(filepath.Join(filepath.Clean(jwtpubkeypath), info.Name()))
				if err != nil {
					return fmt.Errorf("token file error: %v", err)
				}
				nameMatch := re.FindStringSubmatch(info.Name())

				if nameMatch == nil || len(nameMatch) < 2 {
					return fmt.Errorf("unexpected lack of substring match in filename %s", info.Name())
				}

				u.pubkeys[nameMatch[1]] = keyData
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("failed to get public key files (%v)", err)
	}
	return nil
}

// Function for fetching the elixir key from the JWK and transform it to []byte
func (u *ValidateFromToken) getjwtpubkey(jwtpubkeyurl string) error {
	re := regexp.MustCompile("/([^/]+)/")
	keyMatch := re.FindStringSubmatch(jwtpubkeyurl)

	if keyMatch == nil {
		return fmt.Errorf("not valid link for key %s", jwtpubkeyurl)
	}

	if len(keyMatch) < 2 {
		return fmt.Errorf("unexpected lack of submatches in %s", jwtpubkeyurl)
	}

	key := keyMatch[1]
	set, err := jwk.Fetch(jwtpubkeyurl)
	if err != nil {
		return fmt.Errorf("jwk.Fetch failed (%v) for %s", err, jwtpubkeyurl)
	}
	keyEl, err := set.Keys[0].Materialize()
	if err != nil {
		return fmt.Errorf("failed to materialize public key (%v)", err)
	}
	pkeyBytes, err := x509.MarshalPKIXPublicKey(keyEl)
	if err != nil {
		return fmt.Errorf("failed to marshal public key (%v)", err)
	}
	log.Debugf("Getting key from %s", jwtpubkeyurl)
	r, err := http.Get(jwtpubkeyurl)
	if err != nil {
		return fmt.Errorf("failed to get JWK (%v)", err)
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read key response (%v)", err)
	}
	defer r.Body.Close()

	var keytype map[string][]map[string]string
	err = json.Unmarshal(b, &keytype)
	if err != nil {
		return fmt.Errorf("failed to unmarshal key response (%v, response was %s)", err, b)
	}
	keyData := pem.EncodeToMemory(
		&pem.Block{
			Type:  keytype["keys"][0]["kty"] + " PUBLIC KEY",
			Bytes: pkeyBytes,
		},
	)
	u.pubkeys[key] = keyData
	log.Debugf("Registered public key for %s", key)
	return nil
}
