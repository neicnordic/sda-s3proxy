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

func TestUserTokenAuthenticator_ReadFile(t *testing.T) {
	var pubkeys map[string][]byte
	jwtpubkeypath := "dummy.ega.nbis.se"
	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)

	assert := assert.New(t)

	err := a.getjwtkey("dev_utils/testing-keys/public-key/")
	if assert.Nil(err) {
		assert.Equal(a.pubkeys[jwtpubkeypath], []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 73, 73, 66, 73, 106, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 79, 67, 65, 81, 56, 65, 77, 73, 73, 66, 67, 103, 75, 67, 65, 81, 69, 65, 110, 122, 121, 105, 115, 49, 90, 106, 102, 78, 66, 48, 98, 66, 103, 75, 70, 77, 83, 118, 10, 118, 107, 84, 116, 119, 108, 118, 66, 115, 97, 74, 113, 55, 83, 53, 119, 65, 43, 107, 122, 101, 86, 79, 86, 112, 86, 87, 119, 107, 87, 100, 86, 104, 97, 52, 115, 51, 56, 88, 77, 47, 112, 97, 47, 121, 114, 52, 55, 97, 118, 55, 43, 122, 51, 86, 84, 109, 118, 68, 82, 121, 65, 72, 99, 10, 97, 84, 57, 50, 119, 104, 82, 69, 70, 112, 76, 118, 57, 99, 106, 53, 108, 84, 101, 74, 83, 105, 98, 121, 114, 47, 77, 114, 109, 47, 89, 116, 106, 67, 90, 86, 87, 103, 97, 79, 89, 73, 104, 119, 114, 88, 119, 75, 76, 113, 80, 114, 47, 49, 49, 105, 110, 87, 115, 65, 107, 102, 73, 121, 10, 116, 118, 72, 87, 84, 120, 90, 89, 69, 99, 88, 76, 103, 65, 88, 70, 117, 85, 117, 97, 83, 51, 117, 70, 57, 103, 69, 105, 78, 81, 119, 122, 71, 84, 85, 49, 118, 48, 70, 113, 107, 113, 84, 66, 114, 52, 66, 56, 110, 87, 51, 72, 67, 78, 52, 55, 88, 85, 117, 48, 116, 56, 89, 48, 10, 101, 43, 108, 102, 52, 115, 52, 79, 120, 81, 97, 119, 87, 68, 55, 57, 74, 57, 47, 53, 100, 51, 82, 121, 48, 118, 98, 86, 51, 65, 109, 49, 70, 116, 71, 74, 105, 74, 118, 79, 119, 82, 115, 73, 102, 86, 67, 104, 68, 112, 89, 83, 116, 84, 99, 72, 84, 67, 77, 113, 116, 118, 87, 98, 10, 86, 54, 76, 49, 49, 66, 87, 107, 112, 122, 71, 88, 83, 87, 52, 72, 118, 52, 51, 113, 97, 43, 71, 83, 89, 79, 68, 50, 81, 85, 54, 56, 77, 98, 53, 57, 111, 83, 107, 50, 79, 66, 43, 66, 116, 79, 76, 112, 74, 111, 102, 109, 98, 71, 69, 71, 103, 118, 109, 119, 121, 67, 73, 57, 10, 77, 119, 73, 68, 65, 81, 65, 66, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10})
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
	jwtpubkeypath := "dev_utils/testing-keys/public-key/"

	a := NewValidateFromToken(pubkeys)
	a.pubkeys = make(map[string][]byte)
	_ = a.getjwtkey(jwtpubkeypath)

	// Set up request defaults
	r, _ := http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2R1bW15LmVnYS5uYmlzLnNlIiwic3ViIjoiZHVtbXkiLCJleHAiOjE3MTk2NzY5ODB9.XjKAkrd8OCV_ApFiMwEIZiYM4a2QFCr4Ik9A3AqPNtV1Mt2IwyMZHrGGuljkf6YT-ZDsk6ONrXxoL5Vifs7px8BULpcoscWtqmW2TM6tKMe0notaXC8kuPMnGK5VEKul1ayibOK0n2QKoOgHzALELQRC44_oOylUoZaQ9OYpuvF8nBf-dn_lSlxsarzDh9iDI95BiXRW9ARvUGtaLESsS-Oar7Z36P8QM3IV-Omiorv8hKrlg1rjCywF5MlWDQSevLiW9Gj_vwBnyKGX06yYlk8J0vJ_yxh-YFZvhzR149MM-3nvHo8CL3LeO4AVRalvRcFnpZgBu60BlZJ7IGIyAA")

	// Test that a user can access their own bucket
	r.URL.Path = "/dummy/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	assert.Nil(t, a.Authenticate(r))

	// Test that a valid user can't access someone elses bucket
	r.URL.Path = "/notvalid/"
	s3signer.SignV4(*r, "username", "testpass", "", "us-east-1")
	otherBucket := a.Authenticate(r)
	assert.Equal(t, "token supplied username dummy but URL had notvalid", otherBucket.Error())

	// Elixir token with wrong username
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczovL2R1bW15LmVnYS5uYmlzLnNlIiwiZXhwIjoxNjkxODUwNzc0LCJpYXQiOjE2Mjg3Nzg4MTUsImp0aSI6IjVlNmM2ZDI0LTQyZWItNDA4ZS1iYTIwLTIwMzkwNGUzODhhMSJ9.hl9A5GQQje-9TICeHFIlek5qi720i6jDu4cHUAtNO9KB4N5iZPw8QiJykWUHo3fDdZtdBfVEDZEe8fnmYXlcn9bt1jUKFUZRMMjm_AyE4RYth3RVg6CFj-KhrxalYVJ4NGl7xts_qI80-vHgf6Ecj0sIJEikPgD4pooPIWiNNwtj3YtqbUslKK2ryaQFT-ZaivEbJsOYjrJr9_925BGw8WTGtqMwspzywoBU3t8G87IIw4yrf4BJXOIn45EFIxaNRoAeuMvrWN_roSFi-oiNxgCzMcdzppyAeVMKP3_WnHyZtLGVKrP3Xs8Wggsmcu5LCFv6dJIp0kuTXINeSb60ng")
	r.URL.Path = "/username/"
	wrongUsername := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", wrongUsername.Error())

	// Expired Elixir token
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkdW1teSIsImF1ZCI6IjE1MTM3NjQ1LTMxNTMtNGQ0OS05ZGRiLTU5NDAyN2NkNGNhNyIsImF6cCI6IjE1MTM3NjQ1LTMxNTMtNGQ0OS05ZGRiLTU5NDAyN2NkNGNhNyIsInNjb3BlIjoiZ2E0Z2hfcGFzc3BvcnRfdjEgb3BlbmlkIiwiaXNzIjoiaHR0cHM6Ly9kdW1teS5lZ2EubmJpcy5zZSIsImV4cCI6MTU2NjIyNTE3NCwiaWF0IjoxNTY1NjIwMzc0LCJqdGkiOiI1ZTZjNmQyNC00MmViLTQwOGUtYmEyMC0yMDM5MDRlMzg4YTEifQ.Ojycuf8UoGm2kcR--LeWlPDSQs23fuBqT2Kq98_rIAsAaZSTkeX3KwwWS0dqRKsIYWbQDfagvGaF4-ZfYk9Lh2lKtaQDLH88DS2vXL3Q3UGi3_ZsSDvdrjV8esEWNX7vlJtm0uRdVh-MJ1Uw3akuCzE5EsUEdgafKx-0aSXA3oJgIoBrFoP92lUIpx0HSyfc-oQOLousbpXDmvt374HUiCRs7lpyg9NmhIy-R68s1nrVAKknz9g8IwsNAAZPNjQgb9_BgOZUs8QELs-2-xJ-XiqHHx3UqFli11fvdDQuOy4OyJg9aJa-BBDzpY50B43UDWF6assiYEeA41HRY1WYCA")
	r.URL.Path = "/dummy/"
	assert.Nil(t, a.Authenticate(r))

	// Expired Elixir token with wrong username
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczovL2R1bW15LmVnYS5uYmlzLnNlIiwiZXhwIjoxNTY2MjI1MTc0LCJpYXQiOjE1NjU2MjAzNzQsImp0aSI6IjVlNmM2ZDI0LTQyZWItNDA4ZS1iYTIwLTIwMzkwNGUzODhhMSJ9.NnYNAHdt5TdogX9teimp3Qv8aibvp45RmZk_tRrLvkl52mn2wi6zkbultdafNhl9Q6iS3qwaevF_eG-OlZ__LlHrS_BUUxYEpblRNptJRLMlkVNkI4r1JPdOjEfLjL6ZDYIu4jHElTZQA-V1Vw3N5KRXvTcYE9zlH_zLfMYW9v5rxlJGRnSe6Bn87KONggAu2MOOcICt-ZKijSF-MD-6T5uyaD0zU0fq6QYAU8WyLuEQGzxF7m3D4eKXvbtzNnaCpLz7mFDawvu_KLawBwatM5AUoNZt9KCIG-fAJvctEcxbfHncfs5E8ZdPrMqQvPiLp2jprFWmMhcicai_N1-t1Q")
	r.URL.Path = "/username/"
	expiredToken := a.Authenticate(r)
	assert.Equal(t, "token supplied username c5773f41d17d27bd53b1e6794aedc32d7906e779@elixir-europe.org but URL had username", expiredToken.Error())

	// Elixir token is not valid (e.g. issued in a future time)
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczovL2R1bW15LmVnYS5uYmlzLnNlIiwiZXhwIjoxNTY2MjI1MTc0LCJpYXQiOjE2NjA5MTk1NzQsImp0aSI6IjVlNmM2ZDI0LTQyZWItNDA4ZS1iYTIwLTIwMzkwNGUzODhhMSJ9.QVFMZvDcLqD0O2O-55Gfqw4mC132UGTKn0eO8Mdf75CSW1tKBL06u5hg1Kf8AiN8xiXJZUh4hmZklpdczqCaEeAx9LuRLQTVY1duv65z1aAfXoMtZtmOQ_dGcQVtEJYApvIMaV2qSa5Vyi5eoKilyWs-UTVfjEOSC_z76RoO2IkkIJWMGu4EY2B2dPdINgud-dtUg95lD1vMw-hm3c3kH1ZWo2Lix7YX09XIltUHuLI_o7NlUm5GxFVkZoZOD_PWo8P3ulcQHQ-LRESEEilk_a-WPUDtI6Cu90USiwwRK3eqRpdgKnoWeIXSpl_yfGf2RjfqTQmCYPAdF0i-lynF_g")
	r.URL.Path = "/username/"
	nonvalidToken := a.Authenticate(r)
	// The error output is huge so a smaller part is compared
	assert.Equal(t, "signed token (RS256) not valid:", nonvalidToken.Error()[0:31])

	// Elixir tokens broken
	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "JraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczpcL1wvbG9naW4uZWxpeGlyLWN6ZWNoLm9yZ1wvb2lkY1wvIiwiZXhwIjoxNTg1ODMxOTEwLCJpYXQiOjE1ODU4MjgzMTAsImp0aSI6IjdkMDU3NTVhLWRkNjktNDRjZS05MzIwLThlOGRiZjIwNzExNSJ9.bOsxAe8F7i78MfI1FBF2Wiy6g_uO74rOCFe3hBe0Qpf-RhswWnI0ys8EDfxJlqbPj39VX1n9gSphgd8ivGzsf0f00OvHqC17RSN0l6J3FUjyyNi2bWmaiejIzIfxXI0Kyyy45cr-NT5F5m95yuA1O-KpTGtRgDK5zDnhj3XIxBvIZX_pzhI9okY6FzL5fH7ZU4LhunP0iBJfgswK6l2Dy6A4fPhfVtZRU1EeJUBVTJ7YIY-FBvRHAGPgpLFvcOeN4WM8R6mwQ3hJcvcVPAjq1769meOkLsWxpPrbMvxfrtRjd4ANrnvwiEH-syV_ELXm2ntqMlFuFdoJ3CXY9pMzgw")
	r.URL.Path = "/username/"
	brokenToken := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken.Error()[0:38])

	r, _ = http.NewRequest("", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Amz-Security-Token", "randomeyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJjNTc3M2Y0MWQxN2QyN2JkNTNiMWU2Nzk0YWVkYzMyZDc5MDZlNzc5QGVsaXhpci1ldXJvcGUub3JnIiwiYXVkIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3IiwiYXpwIjoiMTUxMzc2NDUtMzE1My00ZDQ5LTlkZGItNTk0MDI3Y2Q0Y2E3Iiwic2NvcGUiOiJnYTRnaF9wYXNzcG9ydF92MSBvcGVuaWQiLCJpc3MiOiJodHRwczpcL1wvbG9naW4uZWxpeGlyLWN6ZWNoLm9yZ1wvb2lkY1wvIiwiZXhwIjoxNTg1ODMxOTEwLCJpYXQiOjE1ODU4MjgzMTAsImp0aSI6IjdkMDU3NTVhLWRkNjktNDRjZS05MzIwLThlOGRiZjIwNzExNSJ9.bOsxAe8F7i78MfI1FBF2Wiy6g_uO74rOCFe3hBe0Qpf-RhswWnI0ys8EDfxJlqbPj39VX1n9gSphgd8ivGzsf0f00OvHqC17RSN0l6J3FUjyyNi2bWmaiejIzIfxXI0Kyyy45cr-NT5F5m95yuA1O-KpTGtRgDK5zDnhj3XIxBvIZX_pzhI9okY6FzL5fH7ZU4LhunP0iBJfgswK6l2Dy6A4fPhfVtZRU1EeJUBVTJ7YIY-FBvRHAGPgpLFvcOeN4WM8R6mwQ3hJcvcVPAjq1769meOkLsWxpPrbMvxfrtRjd4ANrnvwiEH-syV_ELXm2ntqMlFuFdoJ3CXY9pMzgw")
	r.URL.Path = "/username/"
	assert.Error(t, a.Authenticate(r))
	brokenToken2 := a.Authenticate(r)
	assert.Equal(t, "broken token (claims are empty): map[]", brokenToken2.Error()[0:38])
}
