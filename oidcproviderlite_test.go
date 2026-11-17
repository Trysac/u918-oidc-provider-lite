package oidcproviderlite_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Trysac/u918-oidc-provider-lite"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	testKey1 *rsa.PrivateKey
	testKey2 *rsa.PrivateKey
	testKey3 *rsa.PrivateKey
)

func TestMain(m *testing.M) {
	var err error
	testKey1, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testKey2, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testKey3, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	m.Run()
}

type staticAuth struct {
	subject  string
	authTime time.Time
	ok       bool
	onLogin  func()
}

func (a *staticAuth) Authenticate(_ *http.Request) (string, time.Time, bool) {
	if !a.ok {
		if a.onLogin != nil {
			a.onLogin()
		}
		return "", time.Time{}, false
	}
	return a.subject, a.authTime, true
}

type staticConsent struct {
	granted []string
	ok      bool
}

func (c *staticConsent) Approve(_ *http.Request, _, _ string, scopes []string) ([]string, bool) {
	if !c.ok {
		return nil, false
	}
	if c.granted != nil {
		return c.granted, true
	}
	return scopes, true
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestOracleGoOIDCAndOAuth2Flow(t *testing.T) {
	ks, err := oidcproviderlite.NewKeySet("k1", testKey1)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	secret := "super-secret-value"
	secretHash := sha256.Sum256([]byte(secret))

	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	cbURL := srv.URL + "/cb"
	prov, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: srv.URL,
		Clients: []oidcproviderlite.Client{
			{
				ID:           "app",
				SecretSHA256: secretHash,
				RedirectURIs: []string{cbURL},
				AllowRefresh: true,
			},
		},
		Authenticator: &staticAuth{subject: "user-1", authTime: time.Now().Add(-time.Minute), ok: true},
		Consent:       &staticConsent{ok: true},
		UserInfo: func(subject string, scopes []string) map[string]any {
			return map[string]any{"email": subject + "@example.test", "scopes": scopes}
		},
		Keys: ks,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler = prov

	ctx := context.Background()
	oidcProv, err := oidc.NewProvider(ctx, srv.URL)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}

	oauthCfg := oauth2.Config{
		ClientID:     "app",
		ClientSecret: secret,
		Endpoint:     oidcProv.Endpoint(),
		RedirectURL:  cbURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess},
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	authURL := oauthCfg.AuthCodeURL(
		"state-xyz",
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce("n-123"),
	)

	resp, err := noRedirectClient().Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if gotIss := loc.Query().Get("iss"); gotIss != srv.URL {
		t.Fatalf("iss = %q, want %q", gotIss, srv.URL)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected non-empty authorization code")
	}

	token, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("oauthCfg.Exchange: %v", err)
	}
	if token.AccessToken == "" || token.RefreshToken == "" {
		t.Fatalf("expected access and refresh tokens, got access=%q refresh=%q", token.AccessToken, token.RefreshToken)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatal("missing id_token in token response")
	}

	idTokenVerifier := oidcProv.Verifier(&oidc.Config{ClientID: "app"})
	idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("idTokenVerifier.Verify: %v", err)
	}
	if idToken.Subject != "user-1" {
		t.Fatalf("Subject = %q, want %q", idToken.Subject, "user-1")
	}
	if idToken.Nonce != "n-123" {
		t.Fatalf("Nonce = %q, want %q", idToken.Nonce, "n-123")
	}
	if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	userInfo, err := oidcProv.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		t.Fatalf("oidcProv.UserInfo: %v", err)
	}
	if userInfo.Subject != "user-1" {
		t.Fatalf("userInfo.Subject = %q, want user-1", userInfo.Subject)
	}
}

func TestPKCEAppendixBAndFailureModes(t *testing.T) {
	ks, _ := oidcproviderlite.NewKeySet("k1", testKey1)
	secret := "sec"
	cb := "https://app.example.test/cb"
	prov, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: "https://idp.example.test",
		Clients: []oidcproviderlite.Client{
			{
				ID:           "app",
				SecretSHA256: sha256.Sum256([]byte(secret)),
				RedirectURIs: []string{cb},
				Public:       true,
			},
		},
		Authenticator: &staticAuth{subject: "user-1", ok: true},
		Keys:          ks,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// 1. Valid RFC 7636 Appendix B challenge + verifier succeeds.
	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=app&redirect_uri="+url.QueryEscape(cb)+"&response_type=code&scope=openid&code_challenge="+challenge+"&code_challenge_method=S256&state=s1", nil)
	w := httptest.NewRecorder()
	prov.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"app"},
		"code":          {code},
		"redirect_uri":  {cb},
		"code_verifier": {verifier},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokW := httptest.NewRecorder()
	prov.ServeHTTP(tokW, tokReq)
	if tokW.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", tokW.Code, tokW.Body.String())
	}

	// 2. Wrong verifier gives 400 with error "invalid_grant".
	w2 := httptest.NewRecorder()
	prov.ServeHTTP(w2, req)
	loc2, _ := url.Parse(w2.Header().Get("Location"))
	code2 := loc2.Query().Get("code")

	badForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"app"},
		"code":          {code2},
		"redirect_uri":  {cb},
		"code_verifier": {"wrong-verifier-that-is-at-least-43-characters-long-xxxx"},
	}
	badReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(badForm.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badW := httptest.NewRecorder()
	prov.ServeHTTP(badW, badReq)
	if badW.Code != http.StatusBadRequest {
		t.Fatalf("bad verifier status = %d, want 400", badW.Code)
	}
	var errResp oidcproviderlite.Error
	_ = json.Unmarshal(badW.Body.Bytes(), &errResp)
	if errResp.Code != "invalid_grant" {
		t.Fatalf("error = %q, want invalid_grant", errResp.Code)
	}

	// 3. code_challenge_method "plain" or missing challenge redirects with error "invalid_request".
	for _, tc := range []struct {
		name  string
		query string
	}{
		{"plain method", "client_id=app&redirect_uri=" + url.QueryEscape(cb) + "&response_type=code&scope=openid&code_challenge=" + challenge + "&code_challenge_method=plain&state=st"},
		{"missing challenge", "client_id=app&redirect_uri=" + url.QueryEscape(cb) + "&response_type=code&scope=openid&code_challenge_method=S256&state=st"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/authorize?"+tc.query, nil)
			rec := httptest.NewRecorder()
			prov.ServeHTTP(rec, r)
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", rec.Code)
			}
			u, _ := url.Parse(rec.Header().Get("Location"))
			if got := u.Query().Get("error"); got != "invalid_request" {
				t.Fatalf("redirect error = %q, want invalid_request", got)
			}
			if got := u.Query().Get("state"); got != "st" {
				t.Fatalf("redirect state = %q, want st", got)
			}
			if got := u.Query().Get("iss"); got != "https://idp.example.test" {
				t.Fatalf("redirect iss = %q, want https://idp.example.test", got)
			}
		})
	}
}

func TestRedirectURIMismatchAndAuthorizeErrors(t *testing.T) {
	ks, _ := oidcproviderlite.NewKeySet("k1", testKey1)
	registeredCB := "https://app.example.test/cb"
	mismatchedCB := "https://app.example.test/cb/extra"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	prov, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: "https://idp.example.test",
		Clients: []oidcproviderlite.Client{
			{
				ID:           "app",
				RedirectURIs: []string{registeredCB},
				Public:       true,
			},
		},
		Authenticator: &staticAuth{subject: "user-1", ok: true},
		Consent:       &staticConsent{ok: false},
		Keys:          ks,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Unknown client_id or mismatched redirect_uri returns 400 with no Location header.
	for _, tc := range []struct {
		name     string
		clientID string
		redirect string
	}{
		{"unknown client", "unknown-app", registeredCB},
		{"redirect_uri extra path", "app", mismatchedCB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/authorize?client_id="+tc.clientID+"&redirect_uri="+url.QueryEscape(tc.redirect)+"&response_type=code&scope=openid&code_challenge="+challenge+"&code_challenge_method=S256", nil)
			w := httptest.NewRecorder()
			prov.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if loc := w.Header().Get("Location"); loc != "" {
				t.Fatalf("Location = %q, want empty", loc)
			}
		})
	}

	// Other authorization errors redirect with error, state and iss.
	for _, tc := range []struct {
		name      string
		query     string
		wantError string
	}{
		{
			name:      "unsupported response_type",
			query:     "client_id=app&redirect_uri=" + url.QueryEscape(registeredCB) + "&response_type=token&scope=openid&code_challenge=" + challenge + "&code_challenge_method=S256&state=s-1",
			wantError: "unsupported_response_type",
		},
		{
			name:      "missing openid scope",
			query:     "client_id=app&redirect_uri=" + url.QueryEscape(registeredCB) + "&response_type=code&scope=profile&code_challenge=" + challenge + "&code_challenge_method=S256&state=s-1",
			wantError: "invalid_scope",
		},
		{
			name:      "consent denied",
			query:     "client_id=app&redirect_uri=" + url.QueryEscape(registeredCB) + "&response_type=code&scope=openid&code_challenge=" + challenge + "&code_challenge_method=S256&state=s-1",
			wantError: "access_denied",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/authorize?"+tc.query, nil)
			w := httptest.NewRecorder()
			prov.ServeHTTP(w, req)
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			u, _ := url.Parse(w.Header().Get("Location"))
			if got := u.Query().Get("error"); got != tc.wantError {
				t.Fatalf("error = %q, want %q", got, tc.wantError)
			}
			if got := u.Query().Get("state"); got != "s-1" {
				t.Fatalf("state = %q, want s-1", got)
			}
			if got := u.Query().Get("iss"); got != "https://idp.example.test" {
				t.Fatalf("iss = %q, want https://idp.example.test", got)
			}
		})
	}
}

func TestCodeReplayRevokesTokensAndCodeExpiry(t *testing.T) {
	ks, _ := oidcproviderlite.NewKeySet("k1", testKey1)
	clock := newFakeClock(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	cb := "https://app.example.test/cb"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	prov, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: "https://idp.example.test",
		Clients: []oidcproviderlite.Client{
			{ID: "app", RedirectURIs: []string{cb}, Public: true},
		},
		Authenticator: &staticAuth{subject: "user-1", ok: true},
		Keys:          ks,
		Clock:         clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Issue first code and exchange it.
	authReq := httptest.NewRequest(http.MethodGet, "/authorize?client_id=app&redirect_uri="+url.QueryEscape(cb)+"&response_type=code&scope=openid&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	authW := httptest.NewRecorder()
	prov.ServeHTTP(authW, authReq)
	loc, _ := url.Parse(authW.Header().Get("Location"))
	code := loc.Query().Get("code")

	exchange := func(c string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"app"},
			"code":          {c},
			"redirect_uri":  {cb},
			"code_verifier": {verifier},
		}
		r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		prov.ServeHTTP(w, r)
		return w
	}

	tokW1 := exchange(code)
	if tokW1.Code != http.StatusOK {
		t.Fatalf("first exchange status = %d", tokW1.Code)
	}
	var tokData map[string]any
	_ = json.Unmarshal(tokW1.Body.Bytes(), &tokData)
	accessToken := tokData["access_token"].(string)

	// Verify userinfo works before code replay.
	uReq1 := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	uReq1.Header.Set("Authorization", "Bearer "+accessToken)
	uW1 := httptest.NewRecorder()
	prov.ServeHTTP(uW1, uReq1)
	if uW1.Code != http.StatusOK {
		t.Fatalf("userinfo before replay status = %d, want 200", uW1.Code)
	}

	// Replay the authorization code -> 400 "invalid_grant" and revokes access token.
	tokW2 := exchange(code)
	if tokW2.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400", tokW2.Code)
	}
	var errResp oidcproviderlite.Error
	_ = json.Unmarshal(tokW2.Body.Bytes(), &errResp)
	if errResp.Code != "invalid_grant" {
		t.Fatalf("replay error = %q, want invalid_grant", errResp.Code)
	}

	// Userinfo now returns 401.
	uReq2 := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	uReq2.Header.Set("Authorization", "Bearer "+accessToken)
	uW2 := httptest.NewRecorder()
	prov.ServeHTTP(uW2, uReq2)
	if uW2.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo after replay status = %d, want 401", uW2.Code)
	}
	if gotWWW := uW2.Header().Get("WWW-Authenticate"); gotWWW != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate = %q", gotWWW)
	}

	// Issue another code and use it 61s after issue -> "invalid_grant".
	authW2 := httptest.NewRecorder()
	prov.ServeHTTP(authW2, authReq)
	loc2, _ := url.Parse(authW2.Header().Get("Location"))
	codeExp := loc2.Query().Get("code")

	clock.Advance(61 * time.Second)
	tokWExp := exchange(codeExp)
	if tokWExp.Code != http.StatusBadRequest {
		t.Fatalf("expired code status = %d, want 400", tokWExp.Code)
	}
	_ = json.Unmarshal(tokWExp.Body.Bytes(), &errResp)
	if errResp.Code != "invalid_grant" {
		t.Fatalf("expired code error = %q, want invalid_grant", errResp.Code)
	}
}

func TestRefreshTokenRotationAndFamilyRevocation(t *testing.T) {
	ks, _ := oidcproviderlite.NewKeySet("k1", testKey1)
	cb := "https://app.example.test/cb"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	prov, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: "https://idp.example.test",
		Clients: []oidcproviderlite.Client{
			{ID: "app", RedirectURIs: []string{cb}, Public: true, AllowRefresh: true},
		},
		Authenticator: &staticAuth{subject: "user-1", ok: true},
		Keys:          ks,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/authorize?client_id=app&redirect_uri="+url.QueryEscape(cb)+"&response_type=code&scope=openid+offline_access&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	authW := httptest.NewRecorder()
	prov.ServeHTTP(authW, authReq)
	loc, _ := url.Parse(authW.Header().Get("Location"))
	code := loc.Query().Get("code")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"app"},
		"code":          {code},
		"redirect_uri":  {cb},
		"code_verifier": {verifier},
	}
	r1 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	prov.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("initial token status = %d", w1.Code)
	}
	var tok1 map[string]any
	_ = json.Unmarshal(w1.Body.Bytes(), &tok1)
	rt1 := tok1["refresh_token"].(string)

	refreshCall := func(rt string) (*httptest.ResponseRecorder, map[string]any) {
		rf := url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {"app"},
			"refresh_token": {rt},
		}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(rf.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		prov.ServeHTTP(w, req)
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w, body
	}

	// 1. First refresh succeeds and rotates refresh token.
	w2, tok2 := refreshCall(rt1)
	if w2.Code != http.StatusOK {
		t.Fatalf("refresh 1 status = %d", w2.Code)
	}
	rt2 := tok2["refresh_token"].(string)
	if rt2 == "" || rt2 == rt1 {
		t.Fatalf("expected new refresh token, got %q", rt2)
	}

	// 2. Presenting old refresh token rt1 returns "invalid_grant" and revokes family.
	wOld, bodyOld := refreshCall(rt1)
	if wOld.Code != http.StatusBadRequest || bodyOld["error"] != "invalid_grant" {
		t.Fatalf("old refresh status = %d, error = %v", wOld.Code, bodyOld["error"])
	}

	// 3. Presenting the newly issued rt2 now also fails with "invalid_grant".
	wNew, bodyNew := refreshCall(rt2)
	if wNew.Code != http.StatusBadRequest || bodyNew["error"] != "invalid_grant" {
		t.Fatalf("revoked family refresh status = %d, error = %v", wNew.Code, bodyNew["error"])
	}
}

func TestKeyRotationJWKSOrderAndVerification(t *testing.T) {
	ks, err := oidcproviderlite.NewKeySet("k1", testKey1)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	cb := srv.URL + "/cb"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	prov, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: srv.URL,
		Clients: []oidcproviderlite.Client{
			{ID: "app", RedirectURIs: []string{cb}, Public: true},
		},
		Authenticator: &staticAuth{subject: "user-1", ok: true},
		Keys:          ks,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler = prov

	issueIDToken := func() string {
		resp, err := noRedirectClient().Get(srv.URL + "/authorize?client_id=app&redirect_uri=" + url.QueryEscape(cb) + "&response_type=code&scope=openid&code_challenge=" + challenge + "&code_challenge_method=S256")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		defer resp.Body.Close()
		u, _ := url.Parse(resp.Header.Get("Location"))
		code := u.Query().Get("code")

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"app"},
			"code":          {code},
			"redirect_uri":  {cb},
			"code_verifier": {verifier},
		}
		tokResp, err := http.PostForm(srv.URL+"/token", form)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		defer tokResp.Body.Close()
		var data map[string]any
		_ = json.NewDecoder(tokResp.Body).Decode(&data)
		return data["id_token"].(string)
	}

	idTokenK1 := issueIDToken()

	// Rotate to k2.
	if err := ks.Rotate("k2", testKey2); err != nil {
		t.Fatalf("Rotate k2: %v", err)
	}

	jwksKids := func() []string {
		r, err := http.Get(srv.URL + "/jwks.json")
		if err != nil {
			t.Fatalf("GET jwks: %v", err)
		}
		defer r.Body.Close()
		var doc struct {
			Keys []struct {
				Kid string `json:"kid"`
			} `json:"keys"`
		}
		_ = json.NewDecoder(r.Body).Decode(&doc)
		out := make([]string, len(doc.Keys))
		for i, k := range doc.Keys {
			out[i] = k.Kid
		}
		return out
	}

	kids := jwksKids()
	if len(kids) != 2 || kids[0] != "k2" || kids[1] != "k1" {
		t.Fatalf("jwks kids = %v, want [k2 k1]", kids)
	}

	// Verify idTokenK1 signed before rotation still verifies with go-oidc.
	ctx := context.Background()
	oidcProv, err := oidc.NewProvider(ctx, srv.URL)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	v := oidcProv.Verifier(&oidc.Config{ClientID: "app"})
	if _, err := v.Verify(ctx, idTokenK1); err != nil {
		t.Fatalf("Verify k1 token after rotation: %v", err)
	}

	// Issue new token and check header kid is "k2".
	idTokenK2 := issueIDToken()
	if _, err := v.Verify(ctx, idTokenK2); err != nil {
		t.Fatalf("Verify k2 token: %v", err)
	}
	parts := strings.Split(idTokenK2, ".")
	hdrBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr map[string]string
	_ = json.Unmarshal(hdrBytes, &hdr)
	if hdr["kid"] != "k2" {
		t.Fatalf("new token kid = %q, want k2", hdr["kid"])
	}

	// Third rotation drops k1.
	if err := ks.Rotate("k3", testKey3); err != nil {
		t.Fatalf("Rotate k3: %v", err)
	}
	kidsAfter3 := jwksKids()
	if len(kidsAfter3) != 2 || kidsAfter3[0] != "k3" || kidsAfter3[1] != "k2" {
		t.Fatalf("jwks kids after 3rd rotation = %v, want [k3 k2]", kidsAfter3)
	}
}

func TestClientAuthAndDiscoveryMetadata(t *testing.T) {
	ks, _ := oidcproviderlite.NewKeySet("k1", testKey1)
	secretHash := sha256.Sum256([]byte("correct-secret"))
	prov, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: "https://idp.example.test",
		Clients: []oidcproviderlite.Client{
			{
				ID:           "conf-app",
				SecretSHA256: secretHash,
				RedirectURIs: []string{"https://app.example.test/cb"},
			},
		},
		Authenticator: &staticAuth{subject: "user-1", ok: true},
		Keys:          ks,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Wrong client secret via Basic returns 401 with error "invalid_client" and WWW-Authenticate Basic.
	form := url.Values{"grant_type": {"authorization_code"}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("conf-app", "wrong-secret")
	w := httptest.NewRecorder()
	prov.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if gotWWW := w.Header().Get("WWW-Authenticate"); gotWWW != "Basic realm=\"oidc\"" {
		t.Fatalf("WWW-Authenticate = %q, want %q", gotWWW, "Basic realm=\"oidc\"")
	}
	_ = "Basic realm=\""
	var errResp oidcproviderlite.Error
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Code != "invalid_client" {
		t.Fatalf("error = %q, want invalid_client", errResp.Code)
	}

	// Check /.well-known/openid-configuration fields.
	discReq := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	discW := httptest.NewRecorder()
	prov.ServeHTTP(discW, discReq)
	if discW.Code != http.StatusOK {
		t.Fatalf("discovery status = %d", discW.Code)
	}
	var meta map[string]any
	_ = json.Unmarshal(discW.Body.Bytes(), &meta)

	checkSlice := func(field, want string) {
		arr, ok := meta[field].([]any)
		if !ok || len(arr) != 1 || arr[0] != want {
			t.Fatalf("%s = %v, want [%q]", field, meta[field], want)
		}
	}
	checkSlice("code_challenge_methods_supported", "S256")
	checkSlice("response_types_supported", "code")
	checkSlice("id_token_signing_alg_values_supported", "RS256")
}

func TestOnEventSanitizationAndMaxCodesCap(t *testing.T) {
	ks, _ := oidcproviderlite.NewKeySet("k1", testKey1)
	secret := "top-secret-client-credential"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	cb := "https://app.example.test/cb"

	var events []oidcproviderlite.Event
	prov, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: "https://idp.example.test",
		Clients: []oidcproviderlite.Client{
			{
				ID:           "app",
				SecretSHA256: sha256.Sum256([]byte(secret)),
				RedirectURIs: []string{cb},
				AllowRefresh: true,
			},
		},
		Authenticator: &staticAuth{subject: "user-1", ok: true},
		Keys:          ks,
		MaxCodes:      2,
		MaxTokens:     2,
		OnEvent: func(e oidcproviderlite.Event) {
			events = append(events, e)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	authorize := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/authorize?client_id=app&redirect_uri="+url.QueryEscape(cb)+"&response_type=code&scope=openid+offline_access&code_challenge="+challenge+"&code_challenge_method=S256", nil)
		w := httptest.NewRecorder()
		prov.ServeHTTP(w, r)
		return w
	}

	w1 := authorize()
	u1, _ := url.Parse(w1.Header().Get("Location"))
	code1 := u1.Query().Get("code")

	w2 := authorize()
	u2, _ := url.Parse(w2.Header().Get("Location"))
	code2 := u2.Query().Get("code")

	// Third pending authorization with MaxCodes=2 returns "temporarily_unavailable".
	w3 := authorize()
	u3, _ := url.Parse(w3.Header().Get("Location"))
	if gotErr := u3.Query().Get("error"); gotErr != "temporarily_unavailable" {
		t.Fatalf("3rd pending code error = %q, want temporarily_unavailable", gotErr)
	}

	// Exchange code1 via client_secret_post.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"app"},
		"client_secret": {secret},
		"code":          {code1},
		"redirect_uri":  {cb},
		"code_verifier": {verifier},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokW := httptest.NewRecorder()
	prov.ServeHTTP(tokW, tokReq)
	if tokW.Code != http.StatusOK {
		t.Fatalf("exchange 1 status = %d: %s", tokW.Code, tokW.Body.String())
	}
	var tokResp map[string]any
	_ = json.Unmarshal(tokW.Body.Bytes(), &tokResp)
	accessToken := tokResp["access_token"].(string)
	refreshToken := tokResp["refresh_token"].(string)

	// Exchange code2 when MaxTokens=2 is already full -> 503 temporarily_unavailable.
	form.Set("code", code2)
	tokReq2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokW2 := httptest.NewRecorder()
	prov.ServeHTTP(tokW2, tokReq2)
	if tokW2.Code != http.StatusServiceUnavailable {
		t.Fatalf("token cap status = %d, want 503", tokW2.Code)
	}

	// Verify OnEvent never contains codes, tokens, secrets, or verifiers.
	sensitive := []string{code1, code2, accessToken, refreshToken, secret, verifier}
	for _, ev := range events {
		combined := ev.Kind + "|" + ev.ClientID + "|" + ev.Subject + "|" + ev.Error
		for _, s := range sensitive {
			if s != "" && strings.Contains(combined, s) {
				t.Fatalf("event %+v leaked sensitive value %q", ev, s)
			}
		}
	}
}

func TestValidationAndEdgeCases(t *testing.T) {
	ks, _ := oidcproviderlite.NewKeySet("k1", testKey1)

	// Key validation errors.
	if _, err := oidcproviderlite.NewKeySet("", testKey1); !errors.Is(err, oidcproviderlite.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for empty kid, got %v", err)
	}
	if _, err := oidcproviderlite.NewKeySet("k1", nil); !errors.Is(err, oidcproviderlite.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for nil key, got %v", err)
	}
	smallKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := oidcproviderlite.NewKeySet("k1", smallKey); !errors.Is(err, oidcproviderlite.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for 1024-bit key, got %v", err)
	}
	if err := ks.Rotate("k1", testKey2); !errors.Is(err, oidcproviderlite.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for duplicate kid rotation, got %v", err)
	}
	var nilKS *oidcproviderlite.KeySet
	if err := nilKS.Rotate("k2", testKey2); !errors.Is(err, oidcproviderlite.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for nil KeySet, got %v", err)
	}

	// Config validation errors.
	validClient := oidcproviderlite.Client{ID: "c1", RedirectURIs: []string{"https://app.example.test/cb"}, Public: true}
	auth := &staticAuth{subject: "u1", ok: true}

	badConfigs := []oidcproviderlite.Config{
		{Clients: []oidcproviderlite.Client{validClient}, Authenticator: auth, Keys: ks},
		{Issuer: "ftp://bad", Clients: []oidcproviderlite.Client{validClient}, Authenticator: auth, Keys: ks},
		{Issuer: "https://idp.example.test", Clients: []oidcproviderlite.Client{validClient}, Keys: ks},
		{Issuer: "https://idp.example.test", Clients: []oidcproviderlite.Client{validClient}, Authenticator: auth},
		{Issuer: "https://idp.example.test", Authenticator: auth, Keys: ks},
		{Issuer: "https://idp.example.test", Clients: []oidcproviderlite.Client{{ID: ""}}, Authenticator: auth, Keys: ks},
		{Issuer: "https://idp.example.test", Clients: []oidcproviderlite.Client{validClient, validClient}, Authenticator: auth, Keys: ks},
		{Issuer: "https://idp.example.test", Clients: []oidcproviderlite.Client{{ID: "c", Public: true}}, Authenticator: auth, Keys: ks},
		{Issuer: "https://idp.example.test", Clients: []oidcproviderlite.Client{{ID: "c", RedirectURIs: []string{"https://app.example.test/cb#frag"}, Public: true}}, Authenticator: auth, Keys: ks},
		{Issuer: "https://idp.example.test", Clients: []oidcproviderlite.Client{{ID: "c", RedirectURIs: []string{"https://app.example.test/cb"}, Public: false}}, Authenticator: auth, Keys: ks},
	}
	for i, cfg := range badConfigs {
		if _, err := oidcproviderlite.New(cfg); !errors.Is(err, oidcproviderlite.ErrInvalidConfig) {
			t.Fatalf("case %d: expected ErrInvalidConfig, got %v", i, err)
		}
	}

	// Error formatting and matching.
	e := &oidcproviderlite.Error{Code: "test_code"}
	if e.Error() != "oidcproviderlite: test_code" {
		t.Fatalf("Error() = %q", e.Error())
	}
	var nilErr *oidcproviderlite.Error
	if nilErr.Error() != "" || nilErr.Is(oidcproviderlite.ErrInvalidConfig) {
		t.Fatal("nil Error behavior unexpected")
	}

	// Method not allowed, 404, POST /userinfo, unauthenticated flow.
	loginCalled := false
	prov, _ := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer:        "https://idp.example.test",
		Clients:       []oidcproviderlite.Client{validClient},
		Authenticator: &staticAuth{ok: false, onLogin: func() { loginCalled = true }},
		Keys:          ks,
	})

	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	rUnauth := httptest.NewRequest(http.MethodGet, "/authorize?client_id=c1&redirect_uri="+url.QueryEscape("https://app.example.test/cb")+"&response_type=code&scope=openid&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	wUnauth := httptest.NewRecorder()
	prov.ServeHTTP(wUnauth, rUnauth)
	if !loginCalled {
		t.Fatal("expected Authenticator.Authenticate to be called and write login response")
	}

	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/.well-known/openid-configuration", http.StatusMethodNotAllowed},
		{http.MethodPost, "/jwks.json", http.StatusMethodNotAllowed},
		{http.MethodPost, "/authorize", http.StatusMethodNotAllowed},
		{http.MethodGet, "/token", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/userinfo", http.StatusMethodNotAllowed},
		{http.MethodGet, "/unknown", http.StatusNotFound},
	} {
		w := httptest.NewRecorder()
		prov.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s %s = %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}

	// Unsupported grant_type on /token.
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"c1"}}
	rGrant := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	rGrant.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wGrant := httptest.NewRecorder()
	prov.ServeHTTP(wGrant, rGrant)
	if wGrant.Code != http.StatusBadRequest {
		t.Fatalf("unsupported grant status = %d", wGrant.Code)
	}

	// Refresh grant on client with AllowRefresh=false.
	formRef := url.Values{"grant_type": {"refresh_token"}, "client_id": {"c1"}, "refresh_token": {"tok"}}
	rRef := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formRef.Encode()))
	rRef.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wRef := httptest.NewRecorder()
	prov.ServeHTTP(wRef, rRef)
	if wRef.Code != http.StatusBadRequest {
		t.Fatalf("disallowed refresh status = %d", wRef.Code)
	}

	// Failing io.Reader on Rand.
	provFailRand, _ := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer:        "https://idp.example.test",
		Clients:       []oidcproviderlite.Client{validClient},
		Authenticator: &staticAuth{subject: "u1", ok: true},
		Keys:          ks,
		Rand:          iotestErrReader{},
	})
	wFail := httptest.NewRecorder()
	provFailRand.ServeHTTP(wFail, rUnauth)
	if wFail.Code != http.StatusFound {
		t.Fatalf("expected error redirect on Rand failure, got %d", wFail.Code)
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func ExampleNew() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ks, _ := oidcproviderlite.NewKeySet("k1", key)
	provider, err := oidcproviderlite.New(oidcproviderlite.Config{
		Issuer: "https://idp.example.test",
		Clients: []oidcproviderlite.Client{
			{ID: "app", RedirectURIs: []string{"https://app.example.test/cb"}, Public: true},
		},
		Authenticator: &staticAuth{subject: "user-1", ok: true},
		Keys:          ks,
	})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	provider.ServeHTTP(w, req)
	fmt.Println(err == nil, w.Code)
	// Output:
	// true 200
}
