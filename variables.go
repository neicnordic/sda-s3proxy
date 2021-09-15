package main

import (
	"time"
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
)
