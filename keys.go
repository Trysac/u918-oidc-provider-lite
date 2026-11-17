package oidcproviderlite

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"sync"
)

// KeySet manages the current and previous RSA signing keys for ID tokens and
// serves their public parameters as an RFC 7517 JSON Web Key Set.
type KeySet struct {
	mu       sync.RWMutex
	current  keyEntry
	previous *keyEntry
}

type keyEntry struct {
	kid string
	key *rsa.PrivateKey
	jwk jwkPublic
}

type jwkPublic struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwkPublic `json:"keys"`
}

// NewKeySet validates the initial RSA key (2048 to 4096 bits) and constructs a KeySet.
func NewKeySet(kid string, key *rsa.PrivateKey) (*KeySet, error) {
	entry, err := makeKeyEntry(kid, key)
	if err != nil {
		return nil, err
	}
	return &KeySet{current: entry}, nil
}

// Rotate installs a new primary signing key while retaining the immediately
// preceding key in the published JWKS for seamless verification of existing tokens.
// A subsequent call to Rotate drops the older previous key.
func (ks *KeySet) Rotate(kid string, key *rsa.PrivateKey) error {
	if ks == nil {
		return newError(ErrInvalidKey.Code, "key set is nil")
	}
	entry, err := makeKeyEntry(kid, key)
	if err != nil {
		return err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if entry.kid == ks.current.kid {
		return newError(ErrInvalidKey.Code, "new kid must differ from current kid")
	}
	prev := ks.current
	ks.previous = &prev
	ks.current = entry
	return nil
}

func makeKeyEntry(kid string, key *rsa.PrivateKey) (keyEntry, error) {
	trimmed := strings.TrimSpace(kid)
	if trimmed == "" || len(trimmed) > 128 {
		return keyEntry{}, newError(ErrInvalidKey.Code, "kid must be non-empty and at most 128 characters")
	}
	if key == nil || key.N == nil {
		return keyEntry{}, newError(ErrInvalidKey.Code, "rsa private key is required")
	}
	bits := key.N.BitLen()
	if bits < 2048 || bits > 4096 {
		return keyEntry{}, newError(ErrInvalidKey.Code, "rsa key size must be between 2048 and 4096 bits")
	}
	if err := key.Validate(); err != nil {
		return keyEntry{}, newError(ErrInvalidKey.Code, "rsa private key failed validation")
	}
	nBytes := key.PublicKey.N.Bytes()
	eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()
	return keyEntry{
		kid: trimmed,
		key: key,
		jwk: jwkPublic{
			Kty: "RSA",
			Kid: trimmed,
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(nBytes),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		},
	}, nil
}

func (ks *KeySet) jwks() jwksDocument {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	keys := make([]jwkPublic, 0, 2)
	keys = append(keys, ks.current.jwk)
	if ks.previous != nil {
		keys = append(keys, ks.previous.jwk)
	}
	return jwksDocument{Keys: keys}
}

func (ks *KeySet) signJWT(randReader io.Reader, claims map[string]any) (string, error) {
	ks.mu.RLock()
	curr := ks.current
	ks.mu.RUnlock()

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": curr.kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	if randReader == nil {
		randReader = rand.Reader
	}
	sig, err := rsa.SignPKCS1v15(randReader, curr.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
