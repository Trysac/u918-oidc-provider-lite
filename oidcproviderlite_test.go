package oidcproviderlite_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Trysac/u918-oidc-provider-lite"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "trims and lower-cases", input: "  Hello World ", want: "hello world"},
		{name: "already normal", input: "abc", want: "abc"},
		{name: "keeps inner spacing", input: "A  B", want: "a  b"},
		{name: "tabs and newlines are whitespace", input: "\tX\n", want: "x"},
		{name: "empty is rejected", input: "", wantErr: oidcproviderlite.ErrBlank},
		{name: "whitespace only is rejected", input: " \t\n ", wantErr: oidcproviderlite.ErrBlank},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := oidcproviderlite.Normalize(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Normalize(%q) error = %v, want %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestErrBlankMessage(t *testing.T) {
	if got, want := oidcproviderlite.ErrBlank.Error(), "oidcproviderlite: input is blank"; got != want {
		t.Fatalf("ErrBlank.Error() = %q, want %q", got, want)
	}
}

func ExampleNormalize() {
	out, _ := oidcproviderlite.Normalize("  Hello World ")
	fmt.Println(out)

	_, err := oidcproviderlite.Normalize("   ")
	fmt.Println("rejected:", err)
	// Output:
	// hello world
	// rejected: oidcproviderlite: input is blank
}
