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
	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)

	assert := assert.New(t)

	err := a.getjwtkey("dev_utils/keys/")
	if assert.Nil(err) {
		assert.Equal(a.pubkeys[jwtpubkeypath], []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 47, 107, 101, 116, 116, 69, 72, 84, 50, 112, 112, 73, 75, 49, 70, 101, 54, 89, 65, 69, 66, 85, 70, 119, 53, 114, 103, 50, 10, 87, 101, 108, 51, 79, 80, 78, 55, 56, 106, 69, 48, 98, 89, 105, 111, 90, 57, 78, 71, 107, 55, 111, 79, 100, 111, 114, 55, 78, 43, 76, 108, 100, 87, 73, 85, 49, 89, 66, 120, 102, 68, 65, 119, 112, 116, 49, 81, 117, 112, 71, 47, 70, 78, 110, 89, 100, 103, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10})
	}
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

func TestUserTokenAuthenticator_ValidateSignature(t *testing.T) {
	// These tests should be possible to reuse with all correct authenticators somehow
	var pubkeys map[string][]byte
	jwtpubkeypath := "dev_utils/keys/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	a.getjwtkey(jwtpubkeypath)

	// Set up request defaults
	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2R1bW15LmVnYS5uYmlzLnNlIiwic3ViIjoiZHVtbXkiLCJleHAiOjE2MTk2NzY5ODB9.CplalxMMMF_96jFpVM61TrhjCKiAK6Y2jdhe3THJJKDRk4y-WnlQmidyFeec9n__OQH_rWtlE3G6sJb1GSS9Wg")

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
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2R1bW15LmVnYS5uYmlzLnNlIiwic3ViIjoiZHVtbXkiLCJleHAiOjE2MTk2NzY5ODB9.CplalxMMMF_96jFpVM61TrhjCKiAK6Y2jdhe3THJJKDRk4y-WnlQmidyFeec9n__OQH_rWtlE3G6sJb1GSS9Wg")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))

	// Elixir token with wrong username
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczpcL1wvbG9naW4uZWxpeGlyLWN6ZWNoLm9yZ1wvb2lkY1wvIiwiZXhwIjoxNTg1ODQ1Mjc5LCJpYXQiOjE1ODU4NDE2NzksImp0aSI6IjVlNmM2ZDI0LTQyZWItNDA4ZS1iYTIwLTIwMzkwNGUzODhhMSJ9.rRaUcMIl0dQcAUAvGqMmG_B0hSGfP0srdBfAfTksPMItO6-7FpdQ8qtbEJ6avGMsLCJwlIDUuiqHUdXBHVEHdYeP23KfnRnv9ARXt6CsmR4049kHoSMWYNMlo7B6fOh2edA4r-w2e9ENkXCXNSFKg59mQfnUh55K3kmGsQEdAztA0YMJD_QbtmyCAaLAR_lDayJ4mPid6FxmtXaNiPyhoaBTBPZnQx1NBnPWVlvlAMZKALq4BZS5cj8emAa116cj8x1CLrx7UztdjbVqDv3EVXEJOfQczC8RlzS6BTaps_7KMfH2AAMqyMUYHU5N_3o7JZgM9atp0nMAR5U3HcSqRg")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))

	// Elixir token not valid
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczpcL1wvbG9naW4uZWxpeGlyLWN6ZWNoLm9yZ1wvb2lkY1wvIiwiZXhwIjoxNTg1ODMxOTEwLCJpYXQiOjE1ODU4MjgzMTAsImp0aSI6IjdkMDU3NTVhLWRkNjktNDRjZS05MzIwLThlOGRiZjIwNzExNSJ9.bOsxAe8F7i78MfI1FBF2Wiy6g_uO74rOCFe3hBe0Qpf-RhswWnI0ys8EDfxJlqbPj39VX1n9gSphgd8ivGzsf0f00OvHqC17RSN0l6J3FUjyyNi2bWmaiejIzIfxXI0Kyyy45cr-NT5F5m95yuA1O-KpTGtRgDK5zDnhj3XIxBvIZX_pzhI9okY6FzL5fH7ZU4LhunP0iBJfgswK6l2Dy6A4fPhfVtZRU1EeJUBVTJ7YIY-FBvRHAGPgpLFvcOeN4WM8R6mwQ3hJcvcVPAjq1769meOkLsWxpPrbMvxfrtRjd4ANrnvwiEH-syV_ELXm2ntqMlFuFdoJ3CXY9pMzgw")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))
}
