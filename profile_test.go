package masker

import (
	"reflect"
	"testing"
)

type securePayload struct {
	Password      string
	APIKey        string
	ClientSecret  []byte
	Authorization int
	Visible       string
	Identifier    string `mask:"preserveEnds(2,2)"`
}

func TestSecureProfileFullyRedactsCredentials(t *testing.T) {
	m, err := NewSecure(
		WithProfile(ProfileNone),
		WithCache(true),
		WithMaskField("api_key", "preserveEnds(2,2)"),
		WithMaskStringFunc(MaskTypeRedact, func(_, value string) (string, error) {
			return value, nil
		}),
		WithMaskAnyFunc(MaskTypeRedact, func(_ string, value any) (any, error) {
			return value, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewSecure: %v", err)
	}
	if !m.Frozen() {
		t.Fatal("NewSecure masker is not frozen")
	}

	input := securePayload{
		Password:      "password-secret",
		APIKey:        "api-key-secret",
		ClientSecret:  []byte("client-secret"),
		Authorization: 42,
		Visible:       "visible",
		Identifier:    "customer-123456",
	}
	maskedAny, err := m.Mask(input)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	masked := maskedAny.(securePayload)

	if masked.Password != RedactedValue || masked.APIKey != RedactedValue {
		t.Fatalf("string credentials not redacted: %#v", masked)
	}
	if string(masked.ClientSecret) != RedactedValue {
		t.Fatalf("client secret = %q, want %q", masked.ClientSecret, RedactedValue)
	}
	if masked.Authorization != 0 {
		t.Fatalf("authorization = %d, want zero", masked.Authorization)
	}
	if masked.Visible != input.Visible {
		t.Fatalf("visible = %q, want %q", masked.Visible, input.Visible)
	}
	if masked.Identifier != "cu***********56" {
		t.Fatalf("identifier = %q, want explicit preserve-ends output", masked.Identifier)
	}
}

func TestSecureProfileMapKeyAliases(t *testing.T) {
	m, err := NewSecure()
	if err != nil {
		t.Fatalf("NewSecure: %v", err)
	}

	aliases := []string{
		"clientSecret",
		"client_secret",
		"ClientSecret",
		"api-key",
		"APIKey",
		"x-api-key",
		"X-API-Key",
		"authorization",
		"Authorization",
		"set-cookie",
		"Set-Cookie",
		"AUTHORIZATION",
		"CLIENT_SECRET",
		"X_API_KEY",
	}
	input := make(map[string]any, len(aliases)+2)
	for _, alias := range aliases {
		input[alias] = "sentinel-" + alias
	}
	input["visible"] = "value"
	input["credentials"] = map[string]any{"nested": "secret"}

	maskedAny, err := m.Mask(input)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	masked := maskedAny.(map[string]any)
	for _, alias := range aliases {
		if masked[alias] != RedactedValue {
			t.Errorf("%s = %#v, want %q", alias, masked[alias], RedactedValue)
		}
	}
	if masked["visible"] != "value" {
		t.Fatalf("visible = %#v, want value", masked["visible"])
	}
	credentials := reflect.ValueOf(masked["credentials"])
	if !credentials.IsValid() || credentials.Kind() != reflect.Map || !credentials.IsNil() {
		t.Fatalf("nested credentials = %#v, want typed zero", masked["credentials"])
	}
}

func TestPreserveEndsUsesInstanceMaskCharacter(t *testing.T) {
	m, err := New(
		WithProfile(ProfileNone),
		WithMaskChar("#"),
		WithMaskField("identifier", "preserveEnds(1,1)"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	maskedAny, err := m.Mask(map[string]string{"identifier": "abcdef"})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if got := maskedAny.(map[string]string)["identifier"]; got != "a####f" {
		t.Fatalf("identifier = %q, want a####f", got)
	}
}

func TestMaskRedactDoesNotLeakLength(t *testing.T) {
	short, err := MaskRedact("", "a")
	if err != nil {
		t.Fatalf("MaskRedact(short): %v", err)
	}
	long, err := MaskRedact("", "a-much-longer-secret")
	if err != nil {
		t.Fatalf("MaskRedact(long): %v", err)
	}
	if short != RedactedValue || long != RedactedValue || short != long {
		t.Fatalf("redaction outputs = %q and %q", short, long)
	}
}
