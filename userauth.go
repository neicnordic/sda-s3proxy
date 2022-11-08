package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat/go-jwx/jwk"
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

	strIss := fmt.Sprintf("%v", claims["iss"])
	// Poor string unescaper for elixir
	strIss = strings.ReplaceAll(strIss, "\\", "")

	log.Debugf("Looking for key for %s", strIss)

	re := regexp.MustCompile(`//([^/]*)`)
	//nolint:nestif
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

	// Check whether token username and filepath match
	re = regexp.MustCompile("/([^/]+)/")
	username := re.FindStringSubmatch(r.URL.Path)[1]
	//nolint:nestif
	// Case for Elixir and CEGA usernames: Replace @ with _ character
	if strings.Contains(fmt.Sprintf("%v", claims["sub"]), "@") {
		claimString := fmt.Sprintf("%v", claims["sub"])
		if strings.ReplaceAll(claimString, "@", "_") != username {
			return nil, fmt.Errorf("token supplied username %s but URL had %s",
				claims["sub"], username)
		}
	} else {
		if claims["sub"] != username {
			return nil, fmt.Errorf("token supplied username %s but URL had %s",
				claims["sub"], username)
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
				keyData, err := os.ReadFile(filepath.Join(filepath.Clean(jwtpubkeypath), info.Name()))
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
	b, err := io.ReadAll(r.Body)
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
