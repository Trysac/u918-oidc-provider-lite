package oidcproviderlite

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	defaultCodeTTL         = 60 * time.Second
	defaultAccessTokenTTL  = 10 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
	defaultMaxCodes        = 10_000
	defaultMaxTokens       = 100_000
	maxRequestBodyBytes    = 16 * 1024
	maxQueryParamLen       = 2048
)

// Authenticator authenticates the end-user on GET /authorize.
// When ok is false, Authenticate has already written the login response or redirect.
type Authenticator interface {
	Authenticate(r *http.Request) (subject string, authTime time.Time, ok bool)
}

// Consent asks whether the authenticated subject approves the requested scopes
// for clientID. When ok is false, the authorization request is denied with "access_denied".
type Consent interface {
	Approve(r *http.Request, subject, clientID string, scopes []string) (granted []string, ok bool)
}

// UserInfo returns additional claims for the /userinfo endpoint for a subject
// and the granted scopes.
type UserInfo func(subject string, scopes []string) map[string]any

// Event describes a security-relevant protocol event emitted via Config.OnEvent.
// It never contains raw codes, tokens, secrets, or PKCE verifiers.
type Event struct {
	Kind     string
	ClientID string
	Subject  string
	Error    string
}

// Client describes an OAuth 2.1 / OpenID Connect relying party registered with the provider.
type Client struct {
	ID           string
	SecretSHA256 [32]byte
	RedirectURIs []string
	Public       bool
	AllowRefresh bool
}

// Config configures a Provider instance.
type Config struct {
	Issuer          string
	Clients         []Client
	Authenticator   Authenticator
	Consent         Consent
	UserInfo        UserInfo
	Keys            *KeySet
	Clock           func() time.Time
	Rand            io.Reader
	CodeTTL         time.Duration
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	MaxCodes        int
	MaxTokens       int
	OnEvent         func(Event)
}

type authCodeRecord struct {
	codeHash    [32]byte
	clientID    string
	redirectURI string
	subject     string
	authTime    time.Time
	scopes      []string
	nonce       string
	challenge   string
	issuedAt    time.Time
	expiresAt   time.Time
	used        bool
	familyID    string
}

type accessTokenRecord struct {
	tokenHash [32]byte
	clientID  string
	subject   string
	scopes    []string
	expiresAt time.Time
	familyID  string
}

type refreshTokenRecord struct {
	tokenHash [32]byte
	clientID  string
	subject   string
	authTime  time.Time
	scopes    []string
	expiresAt time.Time
	used      bool
	familyID  string
}

// Provider is an embeddable OpenID Connect 1.0 provider implementing [http.Handler].
type Provider struct {
	issuer          string
	clients         map[string]Client
	authenticator   Authenticator
	consent         Consent
	userInfo        UserInfo
	keys            *KeySet
	clock           func() time.Time
	rand            io.Reader
	codeTTL         time.Duration
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	maxCodes        int
	maxTokens       int
	onEvent         func(Event)

	mu            sync.Mutex
	codes         map[[32]byte]*authCodeRecord
	accessTokens  map[[32]byte]*accessTokenRecord
	refreshTokens map[[32]byte]*refreshTokenRecord
}

// New validates cfg and returns a ready-to-serve OpenID Connect Provider.
func New(cfg Config) (*Provider, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return nil, newError(ErrInvalidConfig.Code, "issuer is required")
	}
	parsedIss, err := url.Parse(issuer)
	if err != nil || (parsedIss.Scheme != "http" && parsedIss.Scheme != "https") || parsedIss.Host == "" {
		return nil, newError(ErrInvalidConfig.Code, "issuer must be an absolute http or https URL")
	}
	if cfg.Authenticator == nil {
		return nil, newError(ErrInvalidConfig.Code, "authenticator is required")
	}
	if cfg.Keys == nil {
		return nil, newError(ErrInvalidConfig.Code, "keys is required")
	}
	if len(cfg.Clients) == 0 {
		return nil, newError(ErrInvalidConfig.Code, "at least one client is required")
	}

	clientMap := make(map[string]Client, len(cfg.Clients))
	var zeroHash [32]byte
	for _, c := range cfg.Clients {
		if strings.TrimSpace(c.ID) == "" {
			return nil, newError(ErrInvalidConfig.Code, "client ID must not be empty")
		}
		if _, exists := clientMap[c.ID]; exists {
			return nil, newError(ErrInvalidConfig.Code, "duplicate client ID")
		}
		if len(c.RedirectURIs) == 0 {
			return nil, newError(ErrInvalidConfig.Code, "client must register at least one redirect URI")
		}
		for _, ru := range c.RedirectURIs {
			u, err := url.Parse(ru)
			if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
				return nil, newError(ErrInvalidConfig.Code, "redirect URI must be an absolute URI without fragment")
			}
		}
		if !c.Public && c.SecretSHA256 == zeroHash {
			return nil, newError(ErrInvalidConfig.Code, "confidential client requires a non-zero SecretSHA256")
		}
		copied := c
		copied.RedirectURIs = slices.Clone(c.RedirectURIs)
		clientMap[c.ID] = copied
	}

	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	randReader := cfg.Rand
	if randReader == nil {
		randReader = rand.Reader
	}
	codeTTL := cfg.CodeTTL
	if codeTTL <= 0 {
		codeTTL = defaultCodeTTL
	}
	accessTTL := cfg.AccessTokenTTL
	if accessTTL <= 0 {
		accessTTL = defaultAccessTokenTTL
	}
	refreshTTL := cfg.RefreshTokenTTL
	if refreshTTL <= 0 {
		refreshTTL = defaultRefreshTokenTTL
	}
	maxCodes := cfg.MaxCodes
	if maxCodes <= 0 {
		maxCodes = defaultMaxCodes
	}
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}

	return &Provider{
		issuer:          strings.TrimRight(issuer, "/"),
		clients:         clientMap,
		authenticator:   cfg.Authenticator,
		consent:         cfg.Consent,
		userInfo:        cfg.UserInfo,
		keys:            cfg.Keys,
		clock:           clock,
		rand:            randReader,
		codeTTL:         codeTTL,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
		maxCodes:        maxCodes,
		maxTokens:       maxTokens,
		onEvent:         cfg.OnEvent,
		codes:           make(map[[32]byte]*authCodeRecord),
		accessTokens:    make(map[[32]byte]*accessTokenRecord),
		refreshTokens:   make(map[[32]byte]*refreshTokenRecord),
	}, nil
}

// ServeHTTP routes OpenID Connect requests to discovery, JWKS, authorization,
// token, and userinfo handlers.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		p.handleDiscovery(w, r)
	case "/jwks.json":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		p.handleJWKS(w, r)
	case "/authorize":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		p.handleAuthorize(w, r)
	case "/token":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		p.handleToken(w, r)
	case "/userinfo":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		p.handleUserInfo(w, r)
	default:
		writeNotFound(w)
	}
}

func (p *Provider) emit(kind, clientID, subject, errCode string) {
	if p.onEvent != nil {
		p.onEvent(Event{
			Kind:     kind,
			ClientID: clientID,
			Subject:  subject,
			Error:    errCode,
		})
	}
}

type discoveryDocument struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := discoveryDocument{
		Issuer:                           p.issuer,
		AuthorizationEndpoint:            p.issuer + "/authorize",
		TokenEndpoint:                    p.issuer + "/token",
		UserinfoEndpoint:                 p.issuer + "/userinfo",
		JWKSURI:                          p.issuer + "/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		AuthorizationResponseIssParameterSupported: true,
	}
	setHeader(w.Header(), "Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (p *Provider) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	setHeader(w.Header(), "Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p.keys.jwks())
}

func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > maxRequestBodyBytes {
		p.writeDirectErrorPage(w, http.StatusBadRequest, "invalid_request", "query string exceeds maximum length")
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")

	// Step 1: Verify client_id and exact redirect_uri match before any redirect (RFC 6749 Section 4.1.2.1).
	client, ok := p.clients[clientID]
	if !ok || !slices.Contains(client.RedirectURIs, redirectURI) {
		p.emit("authorize_error", clientID, "", "invalid_client_or_redirect")
		p.writeDirectErrorPage(w, http.StatusBadRequest, "invalid_request", "unknown client_id or unregistered redirect_uri")
		return
	}

	if len(state) > maxQueryParamLen || len(q.Get("nonce")) > maxQueryParamLen {
		p.emit("authorize_error", clientID, "", "invalid_request")
		p.redirectAuthorizeError(w, r, redirectURI, state, "invalid_request", "parameter exceeds maximum length")
		return
	}

	// Step 2: response_type must be "code".
	if q.Get("response_type") != "code" {
		p.emit("authorize_error", clientID, "", "unsupported_response_type")
		p.redirectAuthorizeError(w, r, redirectURI, state, "unsupported_response_type", "response_type must be code")
		return
	}

	// Step 3: scope must contain "openid".
	scopes := strings.Fields(q.Get("scope"))
	if !slices.Contains(scopes, "openid") {
		p.emit("authorize_error", clientID, "", "invalid_scope")
		p.redirectAuthorizeError(w, r, redirectURI, state, "invalid_scope", "scope must include openid")
		return
	}

	// Step 4: PKCE S256 challenge required and must be 43 base64url chars.
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if challenge == "" || method != "S256" || !isValidS256Challenge(challenge) {
		p.emit("authorize_error", clientID, "", "invalid_request")
		p.redirectAuthorizeError(w, r, redirectURI, state, "invalid_request", "valid S256 code_challenge is required")
		return
	}

	// Step 5: Authenticate user.
	subject, authTime, authed := p.authenticator.Authenticate(r)
	if !authed {
		p.emit("authorize_unauthenticated", clientID, "", "")
		return
	}
	if strings.TrimSpace(subject) == "" {
		p.emit("authorize_error", clientID, "", "access_denied")
		p.redirectAuthorizeError(w, r, redirectURI, state, "access_denied", "authentication did not yield a subject")
		return
	}

	// Step 6: Consent.
	grantedScopes := scopes
	if p.consent != nil {
		granted, approved := p.consent.Approve(r, subject, clientID, scopes)
		if !approved || !slices.Contains(granted, "openid") {
			p.emit("authorize_error", clientID, subject, "access_denied")
			p.redirectAuthorizeError(w, r, redirectURI, state, "access_denied", "resource owner denied consent")
			return
		}
		grantedScopes = slices.Clone(granted)
	}

	now := p.clock()
	if authTime.IsZero() {
		authTime = now
	}

	codeRaw, codeHash, err := p.generateRandomToken()
	if err != nil {
		p.emit("authorize_error", clientID, subject, "server_error")
		p.redirectAuthorizeError(w, r, redirectURI, state, "server_error", "failed to generate authorization code")
		return
	}
	familyID, _, err := p.generateRandomToken()
	if err != nil {
		p.emit("authorize_error", clientID, subject, "server_error")
		p.redirectAuthorizeError(w, r, redirectURI, state, "server_error", "failed to generate token family")
		return
	}

	p.mu.Lock()
	if len(p.codes) >= p.maxCodes {
		p.purgeExpiredCodesLocked(now)
	}
	if len(p.codes) >= p.maxCodes {
		p.mu.Unlock()
		p.emit("authorize_error", clientID, subject, "temporarily_unavailable")
		p.redirectAuthorizeError(w, r, redirectURI, state, "temporarily_unavailable", "maximum pending authorization codes reached")
		return
	}
	p.codes[codeHash] = &authCodeRecord{
		codeHash:    codeHash,
		clientID:    clientID,
		redirectURI: redirectURI,
		subject:     subject,
		authTime:    authTime,
		scopes:      grantedScopes,
		nonce:       q.Get("nonce"),
		challenge:   challenge,
		issuedAt:    now,
		expiresAt:   now.Add(p.codeTTL),
		familyID:    familyID,
	}
	p.mu.Unlock()

	p.emit("authorize_code_issued", clientID, subject, "")

	target, _ := url.Parse(redirectURI)
	params := target.Query()
	params.Set("code", codeRaw)
	if state != "" {
		params.Set("state", state)
	}
	params.Set("iss", p.issuer)
	target.RawQuery = params.Encode()
	setHeader(w.Header(), "Cache-Control", "no-store")
	redirect(w, target.String(), http.StatusFound)
}

func (p *Provider) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, desc string) {
	target, _ := url.Parse(redirectURI)
	params := target.Query()
	params.Set("error", errCode)
	if desc != "" {
		params.Set("error_description", desc)
	}
	if state != "" {
		params.Set("state", state)
	}
	params.Set("iss", p.issuer)
	target.RawQuery = params.Encode()
	setHeader(w.Header(), "Cache-Control", "no-store")
	redirect(w, target.String(), http.StatusFound)
}

func (p *Provider) writeDirectErrorPage(w http.ResponseWriter, status int, errCode, desc string) {
	setHeader(w.Header(), "Cache-Control", "no-store")
	setHeader(w.Header(), "Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(&Error{Code: errCode, Description: desc})
}

func (p *Provider) writeTokenError(w http.ResponseWriter, status int, basicChallenge bool, errCode, desc string) {
	setHeader(w.Header(), "Cache-Control", "no-store")
	setHeader(w.Header(), "Pragma", "no-cache")
	if basicChallenge {
		setHeader(w.Header(), "WWW-Authenticate", `Basic realm="oidc"`)
	}
	setHeader(w.Header(), "Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(newError(errCode, desc))
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
	if err != nil {
		p.emit("token_error", "", "", "invalid_request")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_request", "malformed form body")
		return
	}
	postForm, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		p.emit("token_error", "", "", "invalid_request")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_request", "malformed form body")
		return
	}

	client, usedBasic, ok := p.authenticateClient(r, postForm)
	if !ok {
		p.emit("token_error", postForm.Get("client_id"), "", "invalid_client")
		p.writeTokenError(w, http.StatusUnauthorized, usedBasic, "invalid_client", "client authentication failed")
		return
	}

	grantType := postForm.Get("grant_type")
	switch grantType {
	case "authorization_code":
		p.handleAuthCodeGrant(w, r, postForm, client)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r, postForm, client)
	default:
		p.emit("token_error", client.ID, "", "unsupported_grant_type")
		p.writeTokenError(w, http.StatusBadRequest, false, "unsupported_grant_type", "grant_type is not supported")
	}
}

func (p *Provider) authenticateClient(r *http.Request, postForm url.Values) (Client, bool, bool) {
	authHeader := getHeader(r.Header, "Authorization")
	postClientID := postForm.Get("client_id")
	postSecret := postForm.Get("client_secret")

	if strings.HasPrefix(authHeader, "Basic ") || strings.HasPrefix(authHeader, "basic ") {
		// Reject requests sending both Basic and body credentials (RFC 6749 Section 2.3).
		if postSecret != "" {
			return Client{}, true, false
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authHeader[6:]))
		if err != nil {
			return Client{}, true, false
		}
		parts := strings.SplitN(string(raw), ":", 2)
		if len(parts) != 2 {
			return Client{}, true, false
		}
		cid, err1 := url.QueryUnescape(parts[0])
		csec, err2 := url.QueryUnescape(parts[1])
		if err1 != nil || err2 != nil {
			return Client{}, true, false
		}
		if postClientID != "" && postClientID != cid {
			return Client{}, true, false
		}
		client, exists := p.clients[cid]
		if !exists || client.Public {
			return Client{}, true, false
		}
		sum := sha256.Sum256([]byte(csec))
		if subtle.ConstantTimeCompare(sum[:], client.SecretSHA256[:]) != 1 {
			return Client{}, true, false
		}
		return client, true, true
	}

	client, exists := p.clients[postClientID]
	if !exists {
		return Client{}, true, false
	}
	if client.Public {
		if postSecret != "" {
			return Client{}, false, false
		}
		return client, false, true
	}
	if postSecret == "" {
		return Client{}, true, false
	}
	sum := sha256.Sum256([]byte(postSecret))
	if subtle.ConstantTimeCompare(sum[:], client.SecretSHA256[:]) != 1 {
		return Client{}, true, false
	}
	return client, false, true
}

func (p *Provider) handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, postForm url.Values, client Client) {
	codeRaw := postForm.Get("code")
	redirectURI := postForm.Get("redirect_uri")
	verifier := postForm.Get("code_verifier")

	if codeRaw == "" || redirectURI == "" || !isValidPKCEVerifier(verifier) {
		p.emit("token_error", client.ID, "", "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "missing or invalid authorization_code parameters")
		return
	}

	codeHash := sha256.Sum256([]byte(codeRaw))
	now := p.clock()

	p.mu.Lock()
	rec, exists := p.codes[codeHash]
	if !exists {
		p.mu.Unlock()
		p.emit("token_error", client.ID, "", "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "unknown authorization code")
		return
	}
	if rec.used {
		// Replay detected: revoke all tokens in the family (RFC 6749 Section 4.1.2).
		p.revokeFamilyLocked(rec.familyID)
		delete(p.codes, codeHash)
		p.mu.Unlock()
		p.emit("code_replay_detected", client.ID, rec.subject, "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "authorization code has already been used")
		return
	}
	rec.used = true
	if now.After(rec.expiresAt) || rec.clientID != client.ID || rec.redirectURI != redirectURI {
		delete(p.codes, codeHash)
		p.mu.Unlock()
		p.emit("token_error", client.ID, rec.subject, "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "authorization code expired or mismatched")
		return
	}
	if !verifyPKCES256(verifier, rec.challenge) {
		delete(p.codes, codeHash)
		p.mu.Unlock()
		p.emit("token_error", client.ID, rec.subject, "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "PKCE code_verifier does not match challenge")
		return
	}
	p.mu.Unlock()

	p.issueTokenResponse(w, client, rec.subject, rec.authTime, rec.scopes, rec.nonce, rec.familyID, now)
}

func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, postForm url.Values, client Client) {
	if !client.AllowRefresh {
		p.emit("token_error", client.ID, "", "unauthorized_client")
		p.writeTokenError(w, http.StatusBadRequest, false, "unauthorized_client", "client is not allowed to refresh tokens")
		return
	}
	rawRefresh := postForm.Get("refresh_token")
	if rawRefresh == "" {
		p.emit("token_error", client.ID, "", "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "missing refresh_token")
		return
	}
	refreshHash := sha256.Sum256([]byte(rawRefresh))
	now := p.clock()

	p.mu.Lock()
	rec, exists := p.refreshTokens[refreshHash]
	if !exists {
		p.mu.Unlock()
		p.emit("token_error", client.ID, "", "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "unknown refresh token")
		return
	}
	if rec.used {
		// Refresh token reuse revokes the entire token family (RFC 9700 Section 4.14.2).
		p.revokeFamilyLocked(rec.familyID)
		p.mu.Unlock()
		p.emit("refresh_token_reuse_detected", client.ID, rec.subject, "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "refresh token has already been rotated")
		return
	}
	rec.used = true
	if now.After(rec.expiresAt) || rec.clientID != client.ID {
		p.revokeFamilyLocked(rec.familyID)
		p.mu.Unlock()
		p.emit("token_error", client.ID, rec.subject, "invalid_grant")
		p.writeTokenError(w, http.StatusBadRequest, false, "invalid_grant", "refresh token expired or mismatched")
		return
	}
	p.mu.Unlock()

	p.issueTokenResponse(w, client, rec.subject, rec.authTime, rec.scopes, "", rec.familyID, now)
}

type tokenEndpointResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope,omitempty"`
}

func (p *Provider) issueTokenResponse(
	w http.ResponseWriter,
	client Client,
	subject string,
	authTime time.Time,
	scopes []string,
	nonce string,
	familyID string,
	now time.Time,
) {
	accessRaw, accessHash, err := p.generateRandomToken()
	if err != nil {
		p.writeTokenError(w, http.StatusInternalServerError, false, "server_error", "failed to generate access token")
		return
	}

	issueRefresh := client.AllowRefresh && slices.Contains(scopes, "offline_access")
	var refreshRaw string
	var refreshHash [32]byte
	if issueRefresh {
		refreshRaw, refreshHash, err = p.generateRandomToken()
		if err != nil {
			p.writeTokenError(w, http.StatusInternalServerError, false, "server_error", "failed to generate refresh token")
			return
		}
	}

	atDigest := sha256.Sum256([]byte(accessRaw))
	atHash := base64.RawURLEncoding.EncodeToString(atDigest[:16])

	claims := map[string]any{
		"iss":       p.issuer,
		"sub":       subject,
		"aud":       client.ID,
		"exp":       now.Add(p.accessTokenTTL).Unix(),
		"iat":       now.Unix(),
		"auth_time": authTime.Unix(),
		"at_hash":   atHash,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	idToken, err := p.keys.signJWT(p.rand, claims)
	if err != nil {
		p.writeTokenError(w, http.StatusInternalServerError, false, "server_error", "failed to sign id_token")
		return
	}

	p.mu.Lock()
	needed := 1
	if issueRefresh {
		needed = 2
	}
	if len(p.accessTokens)+len(p.refreshTokens)+needed > p.maxTokens {
		p.purgeExpiredTokensLocked(now)
	}
	if len(p.accessTokens)+len(p.refreshTokens)+needed > p.maxTokens {
		p.mu.Unlock()
		p.emit("token_error", client.ID, subject, "temporarily_unavailable")
		p.writeTokenError(w, http.StatusServiceUnavailable, false, "temporarily_unavailable", "maximum active tokens reached")
		return
	}
	p.accessTokens[accessHash] = &accessTokenRecord{
		tokenHash: accessHash,
		clientID:  client.ID,
		subject:   subject,
		scopes:    slices.Clone(scopes),
		expiresAt: now.Add(p.accessTokenTTL),
		familyID:  familyID,
	}
	if issueRefresh {
		p.refreshTokens[refreshHash] = &refreshTokenRecord{
			tokenHash: refreshHash,
			clientID:  client.ID,
			subject:   subject,
			authTime:  authTime,
			scopes:    slices.Clone(scopes),
			expiresAt: now.Add(p.refreshTokenTTL),
			familyID:  familyID,
		}
	}
	p.mu.Unlock()

	p.emit("token_issued", client.ID, subject, "")

	resp := tokenEndpointResponse{
		AccessToken:  accessRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.accessTokenTTL / time.Second),
		RefreshToken: refreshRaw,
		IDToken:      idToken,
		Scope:        strings.Join(scopes, " "),
	}
	setHeader(w.Header(), "Cache-Control", "no-store")
	setHeader(w.Header(), "Pragma", "no-cache")
	setHeader(w.Header(), "Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *Provider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := getHeader(r.Header, "Authorization")
	var rawToken string
	if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
		rawToken = strings.TrimSpace(authHeader[7:])
	} else if r.Method == http.MethodPost {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
		if err == nil {
			if vals, err := url.ParseQuery(string(bodyBytes)); err == nil {
				rawToken = vals.Get("access_token")
			}
		}
	}
	if rawToken == "" {
		p.writeUserInfoUnauthorized(w)
		return
	}

	hash := sha256.Sum256([]byte(rawToken))
	now := p.clock()

	p.mu.Lock()
	rec, exists := p.accessTokens[hash]
	if !exists || now.After(rec.expiresAt) {
		if exists {
			delete(p.accessTokens, hash)
		}
		p.mu.Unlock()
		p.writeUserInfoUnauthorized(w)
		return
	}
	subject := rec.subject
	scopes := slices.Clone(rec.scopes)
	p.mu.Unlock()

	claims := map[string]any{"sub": subject}
	if p.userInfo != nil {
		extra := p.userInfo(subject, scopes)
		for k, v := range extra {
			if k != "sub" {
				claims[k] = v
			}
		}
	}
	setHeader(w.Header(), "Cache-Control", "no-store")
	setHeader(w.Header(), "Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(claims)
}

func (p *Provider) writeUserInfoUnauthorized(w http.ResponseWriter) {
	setHeader(w.Header(), "Cache-Control", "no-store")
	setHeader(w.Header(), "WWW-Authenticate", `Bearer error="invalid_token"`)
	setHeader(w.Header(), "Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(newError("invalid_token", "access token is missing, expired, or revoked"))
}

func (p *Provider) revokeFamilyLocked(familyID string) {
	for k, v := range p.accessTokens {
		if v.familyID == familyID {
			delete(p.accessTokens, k)
		}
	}
	for k, v := range p.refreshTokens {
		if v.familyID == familyID {
			delete(p.refreshTokens, k)
		}
	}
}

func (p *Provider) purgeExpiredCodesLocked(now time.Time) {
	for k, v := range p.codes {
		if v.used || now.After(v.expiresAt) {
			delete(p.codes, k)
		}
	}
}

func (p *Provider) purgeExpiredTokensLocked(now time.Time) {
	for k, v := range p.accessTokens {
		if now.After(v.expiresAt) {
			delete(p.accessTokens, k)
		}
	}
	for k, v := range p.refreshTokens {
		if v.used || now.After(v.expiresAt) {
			delete(p.refreshTokens, k)
		}
	}
}

func (p *Provider) generateRandomToken() (string, [32]byte, error) {
	var buf [32]byte
	if p.rand == nil || p.rand == rand.Reader {
		if _, err := rand.Read(buf[:]); err != nil {
			return "", [32]byte{}, err
		}
	} else {
		if _, err := io.ReadFull(p.rand, buf[:]); err != nil {
			return "", [32]byte{}, err
		}
	}
	raw := base64.RawURLEncoding.EncodeToString(buf[:])
	hash := sha256.Sum256([]byte(raw))
	return raw, hash, nil
}

func isValidS256Challenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil && len(decoded) == 32
}

func isValidPKCEVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		isAlphaNum := (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
		isUnreservedPunct := b == '-' || b == '.' || b == '_' || b == '~'
		if !isAlphaNum && !isUnreservedPunct {
			return false
		}
	}
	return true
}

func verifyPKCES256(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func setHeader(h http.Header, key, value string) {
	h[http.CanonicalHeaderKey(key)] = []string{value}
}

func getHeader(h http.Header, key string) string {
	if vals := h[http.CanonicalHeaderKey(key)]; len(vals) > 0 {
		return vals[0]
	}
	for k, v := range h {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	setHeader(w.Header(), "Content-Type", "text/plain; charset=utf-8")
	setHeader(w.Header(), "X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = io.WriteString(w, "method not allowed\n")
}

func writeNotFound(w http.ResponseWriter) {
	setHeader(w.Header(), "Content-Type", "text/plain; charset=utf-8")
	setHeader(w.Header(), "X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "404 page not found\n")
}

func redirect(w http.ResponseWriter, target string, code int) {
	setHeader(w.Header(), "Location", target)
	w.WriteHeader(code)
}
