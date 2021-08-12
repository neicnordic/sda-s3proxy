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
		assert.Equal(a.pubkeys[jwtpubkeypath], []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 73, 73, 67, 73, 106, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 79, 67, 65, 103, 56, 65, 77, 73, 73, 67, 67, 103, 75, 67, 65, 103, 69, 65, 120, 74, 113, 72, 97, 50, 97, 104, 43, 48, 66, 54, 71, 69, 55, 75, 50, 51, 74, 104, 10, 107, 106, 76, 57, 97, 117, 120, 107, 118, 98, 97, 119, 110, 107, 68, 98, 71, 90, 48, 56, 56, 82, 75, 85, 47, 47, 103, 81, 102, 70, 105, 88, 54, 51, 98, 107, 79, 86, 70, 113, 110, 114, 73, 73, 88, 104, 116, 107, 120, 112, 53, 118, 79, 82, 86, 118, 119, 118, 48, 50, 120, 88, 85, 50, 10, 112, 90, 113, 122, 76, 83, 113, 48, 77, 80, 97, 113, 84, 48, 76, 97, 111, 79, 54, 79, 72, 104, 66, 69, 116, 99, 111, 119, 112, 72, 119, 89, 68, 120, 66, 50, 88, 79, 97, 73, 53, 49, 87, 110, 55, 76, 83, 54, 53, 90, 97, 75, 112, 121, 117, 74, 82, 84, 51, 48, 86, 52, 110, 99, 10, 53, 48, 103, 107, 114, 57, 49, 53, 115, 98, 97, 54, 121, 90, 53, 49, 77, 102, 103, 99, 52, 111, 66, 122, 55, 65, 108, 71, 74, 105, 111, 108, 68, 101, 117, 107, 98, 67, 115, 101, 84, 113, 83, 103, 89, 106, 105, 107, 53, 119, 81, 106, 108, 108, 50, 54, 75, 76, 86, 89, 52, 50, 48, 65, 10, 87, 103, 83, 48, 49, 109, 77, 113, 88, 106, 48, 72, 116, 57, 90, 47, 70, 103, 57, 49, 117, 43, 102, 69, 101, 87, 67, 112, 65, 50, 99, 100, 88, 78, 57, 88, 117, 57, 100, 101, 88, 48, 49, 121, 84, 118, 110, 78, 105, 47, 88, 73, 65, 57, 66, 117, 120, 105, 73, 105, 79, 112, 69, 67, 10, 76, 71, 75, 67, 89, 108, 113, 116, 70, 66, 97, 52, 80, 88, 77, 86, 76, 67, 69, 104, 85, 50, 106, 101, 81, 53, 112, 73, 112, 121, 47, 69, 108, 116, 119, 107, 112, 72, 47, 90, 87, 43, 112, 76, 70, 107, 87, 89, 86, 108, 107, 107, 47, 90, 114, 80, 75, 108, 82, 65, 106, 107, 53, 66, 10, 120, 72, 52, 74, 56, 108, 101, 49, 52, 97, 73, 109, 112, 116, 50, 80, 109, 88, 70, 104, 118, 104, 120, 56, 81, 77, 77, 82, 115, 108, 56, 109, 57, 110, 90, 105, 54, 119, 100, 79, 107, 74, 98, 101, 48, 68, 110, 53, 101, 89, 47, 100, 43, 49, 80, 102, 100, 103, 97, 98, 78, 56, 52, 114, 10, 85, 109, 73, 108, 69, 79, 83, 67, 50, 69, 97, 116, 120, 76, 105, 69, 88, 85, 110, 86, 102, 70, 73, 111, 67, 43, 50, 106, 104, 98, 118, 119, 77, 80, 119, 102, 49, 121, 122, 48, 98, 82, 99, 102, 68, 120, 120, 121, 113, 54, 75, 108, 51, 80, 73, 77, 65, 70, 119, 103, 107, 80, 79, 113, 10, 116, 106, 73, 107, 70, 113, 48, 110, 67, 72, 68, 101, 120, 75, 72, 101, 108, 76, 65, 102, 83, 47, 102, 99, 108, 85, 69, 73, 55, 54, 72, 103, 112, 55, 81, 98, 68, 121, 107, 113, 104, 43, 85, 81, 57, 65, 118, 114, 57, 83, 105, 70, 110, 118, 43, 79, 109, 70, 97, 89, 83, 109, 87, 81, 10, 83, 113, 117, 73, 65, 52, 54, 72, 43, 107, 100, 72, 67, 104, 113, 65, 118, 109, 53, 119, 122, 84, 84, 98, 80, 98, 70, 79, 88, 118, 47, 52, 116, 83, 115, 57, 73, 103, 99, 122, 90, 48, 100, 97, 112, 118, 121, 109, 68, 69, 106, 51, 107, 100, 98, 74, 115, 70, 73, 117, 53, 53, 90, 110, 10, 88, 86, 84, 102, 112, 82, 116, 81, 102, 76, 109, 102, 48, 65, 72, 68, 67, 67, 100, 104, 100, 101, 84, 116, 82, 110, 98, 43, 107, 98, 57, 87, 114, 98, 81, 81, 113, 122, 119, 110, 47, 82, 98, 67, 70, 108, 108, 103, 97, 105, 119, 88, 70, 114, 110, 89, 84, 49, 111, 55, 74, 51, 114, 76, 10, 105, 116, 81, 118, 80, 106, 65, 110, 81, 110, 70, 69, 68, 75, 120, 89, 78, 108, 43, 75, 47, 50, 107, 67, 65, 119, 69, 65, 65, 81, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10})
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
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2R1bW15LmVnYS5uYmlzLnNlIiwic3ViIjoiZHVtbXkiLCJleHAiOjE3MTk2NzY5ODB9.oa5Lx9MBe_Fv6sBAg3YnsWau9VQLAcnb-6G_0sNx6857qMSeUKnv4bNE7gZ1FGR60ofoPJZ4Pg2Ni2VyYQ1AwP4LNeCGiQ5vAmdNKwt6QrBrsxAeSK3G4OXRD8uoK9t1iK6Gkk0GMZgjnJF9a5YkhYYYMKY6AcXP3ObV5bufb9s86rcZG_bZ__dudH6QbSCVvDnJrzrAK_5Wzoz8DNwTMDZhCGar4_sraj3_5TeXIUHu0zZGg-4ni9VDQ-EXN7ZJbMKmwB_j9EYLhQGA4oz8BbD3y1h9xkrDkqqZWHYcxW1Kn3ZPGfb-bLlTIjzrLOO7MkSZid4p6cKdcpQ_LV5qALRr-L-GMF4RP8nn47_8mw1olXIFSlr-dp8yladploFIsEiol3Hwjvan9hq8QTWRaOj-SAmGqGnkJ3WkS7TTSlRP3IOXho_UVbRtBfbeE9k17aFjdHZQSd54DtWFQL_ot8khyrJGsNKtsyLdVkE1fflrF3G21Mn_H9LHnieNhahx_zRnCS8z7v1L1x2Xe2h8XHyu-Bu9el2weYcMGIUqDWJAs1i5o0XAN5wRr7q7XVBlCpS6vwnmDvYTdGAW2EwpSLkDcwq5ONPtPF8qF95RYPaGaOHeejN7qNIj-aL2pYfr_qLMFuLYV3LH1J1jhqmcvukMmJNyC72h1s872eeGX0Q")

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

	// Elixir tokens broken
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "JraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczpcL1wvbG9naW4uZWxpeGlyLWN6ZWNoLm9yZ1wvb2lkY1wvIiwiZXhwIjoxNTg1ODMxOTEwLCJpYXQiOjE1ODU4MjgzMTAsImp0aSI6IjdkMDU3NTVhLWRkNjktNDRjZS05MzIwLThlOGRiZjIwNzExNSJ9.bOsxAe8F7i78MfI1FBF2Wiy6g_uO74rOCFe3hBe0Qpf-RhswWnI0ys8EDfxJlqbPj39VX1n9gSphgd8ivGzsf0f00OvHqC17RSN0l6J3FUjyyNi2bWmaiejIzIfxXI0Kyyy45cr-NT5F5m95yuA1O-KpTGtRgDK5zDnhj3XIxBvIZX_pzhI9okY6FzL5fH7ZU4LhunP0iBJfgswK6l2Dy6A4fPhfVtZRU1EeJUBVTJ7YIY-FBvRHAGPgpLFvcOeN4WM8R6mwQ3hJcvcVPAjq1769meOkLsWxpPrbMvxfrtRjd4ANrnvwiEH-syV_ELXm2ntqMlFuFdoJ3CXY9pMzgw")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "randomeyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczpcL1wvbG9naW4uZWxpeGlyLWN6ZWNoLm9yZ1wvb2lkY1wvIiwiZXhwIjoxNTg1ODMxOTEwLCJpYXQiOjE1ODU4MjgzMTAsImp0aSI6IjdkMDU3NTVhLWRkNjktNDRjZS05MzIwLThlOGRiZjIwNzExNSJ9.bOsxAe8F7i78MfI1FBF2Wiy6g_uO74rOCFe3hBe0Qpf-RhswWnI0ys8EDfxJlqbPj39VX1n9gSphgd8ivGzsf0f00OvHqC17RSN0l6J3FUjyyNi2bWmaiejIzIfxXI0Kyyy45cr-NT5F5m95yuA1O-KpTGtRgDK5zDnhj3XIxBvIZX_pzhI9okY6FzL5fH7ZU4LhunP0iBJfgswK6l2Dy6A4fPhfVtZRU1EeJUBVTJ7YIY-FBvRHAGPgpLFvcOeN4WM8R6mwQ3hJcvcVPAjq1769meOkLsWxpPrbMvxfrtRjd4ANrnvwiEH-syV_ELXm2ntqMlFuFdoJ3CXY9pMzgw")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))
}
