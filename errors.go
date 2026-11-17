package oidcproviderlite

import "fmt"

// Error is the base structured error type returned by configuration, key
// management, and protocol validation in oidcproviderlite.
type Error struct {
	// Code is a stable machine-readable error identifier.
	Code string `json:"error"`
	// Description is a human-readable explanation safe for logs and responses.
	Description string `json:"error_description,omitempty"`
}

// Error implements the standard error interface.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Description == "" {
		return fmt.Sprintf("oidcproviderlite: %s", e.Code)
	}
	return fmt.Sprintf("oidcproviderlite: %s: %s", e.Code, e.Description)
}

// Is reports whether target matches this Error by Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || e == nil || t == nil {
		return false
	}
	return e.Code == t.Code && (t.Description == "" || e.Description == t.Description)
}

// Sentinel errors for configuration and key set validation.
var (
	// ErrInvalidConfig indicates invalid provider configuration.
	ErrInvalidConfig = &Error{Code: "invalid_config"}
	// ErrInvalidKey indicates a nil, non-RSA, or insufficiently sized RSA key,
	// or an empty key ID.
	ErrInvalidKey = &Error{Code: "invalid_key"}
)

func newError(code, desc string) *Error {
	if len(desc) > 200 {
		desc = desc[:200]
	}
	return &Error{Code: code, Description: desc}
}
