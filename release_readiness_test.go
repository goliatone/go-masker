package masker

import (
	"errors"
	"fmt"
	"testing"
)

var errMaskRejected = errors.New("mask rejected")

func TestMaskFailureDoesNotReturnInput(t *testing.T) {
	m, err := New(
		WithProfile(ProfileNone),
		WithMaskStringFunc("fail", func(_, _ string) (string, error) {
			return "", errMaskRejected
		}),
		WithMaskField("secret", "fail"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	masked, err := m.Mask(map[string]string{"secret": "sentinel-secret"})
	if !errors.Is(err, errMaskRejected) {
		t.Fatalf("Mask error = %v, want errMaskRejected", err)
	}
	if masked != nil {
		t.Fatalf("Mask returned %#v on failure, want nil", masked)
	}
}

type cyclicPayload struct {
	ClientSecret string
	Next         *cyclicPayload
}

func TestSecureMaskPreservesPointerCycles(t *testing.T) {
	m, err := NewSecure()
	if err != nil {
		t.Fatalf("NewSecure: %v", err)
	}
	input := &cyclicPayload{ClientSecret: "sentinel-secret"}
	input.Next = input

	maskedAny, err := m.Mask(input)
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	masked := maskedAny.(*cyclicPayload)
	if masked == input {
		t.Fatal("Mask returned the input pointer")
	}
	if masked.ClientSecret != RedactedValue {
		t.Fatalf("client secret = %q", masked.ClientSecret)
	}
	if masked.Next != masked {
		t.Fatal("masked pointer cycle was not preserved")
	}
	if input.ClientSecret != "sentinel-secret" || input.Next != input {
		t.Fatal("Mask mutated the cyclic input")
	}
}

func FuzzSecureMaskMap(f *testing.F) {
	aliases := []string{"clientSecret", "api-key", "X-API-Key", "authorization", "Set-Cookie"}
	f.Add(uint8(0), "sentinel-secret")
	f.Add(uint8(3), "Bearer credential")

	f.Fuzz(func(t *testing.T, aliasIndex uint8, secret string) {
		if len(secret) > 4096 {
			t.Skip()
		}
		m, err := NewSecure()
		if err != nil {
			t.Fatalf("NewSecure: %v", err)
		}
		key := aliases[int(aliasIndex)%len(aliases)]
		maskedAny, err := m.Mask(map[string]string{key: secret})
		if err != nil {
			t.Fatalf("Mask: %v", err)
		}
		got := maskedAny.(map[string]string)[key]
		if secret == "" {
			if got != "" {
				t.Fatalf("empty value = %q", got)
			}
			return
		}
		if got != RedactedValue {
			t.Fatalf("masked value = %q for secret length %d", got, len(secret))
		}
	})
}

func FuzzPreserveEnds(f *testing.F) {
	f.Add("abcdef", uint8(1), uint8(1))
	f.Add("åßç∂ƒ", uint8(1), uint8(2))

	f.Fuzz(func(t *testing.T, value string, startRaw, endRaw uint8) {
		if len(value) > 4096 {
			t.Skip()
		}
		start := int(startRaw % 16)
		end := int(endRaw % 16)
		result, err := maskPreserveEnds("*", fmt.Sprintf("(%d,%d)", start, end), value)
		if err != nil {
			t.Fatalf("maskPreserveEnds: %v", err)
		}
		if value == "" && result != "" {
			t.Fatalf("empty input = %q", result)
		}
	})
}

func TestPreserveEndsHandlesNegativeArguments(t *testing.T) {
	result, err := maskPreserveEnds("*", "(-2,-3)", "secret")
	if err != nil {
		t.Fatalf("maskPreserveEnds: %v", err)
	}
	if result != "******" {
		t.Fatalf("result = %q, want full mask", result)
	}
}

func BenchmarkSecureMask(b *testing.B) {
	input := map[string]any{
		"clientSecret": "sentinel-secret",
		"visible":      "value",
		"nested": map[string]any{
			"api_key": "sentinel-api-key",
		},
	}
	for _, cacheEnabled := range []bool{false, true} {
		b.Run(fmt.Sprintf("cache_%t", cacheEnabled), func(b *testing.B) {
			m, err := New(WithProfile(ProfileSecure), WithCache(cacheEnabled))
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			m.Freeze()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := m.Mask(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
