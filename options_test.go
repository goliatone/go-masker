package masker

import (
	"errors"
	"strings"
	"testing"
)

func TestNewCreatesIndependentMaskers(t *testing.T) {
	first, err := New(
		WithProfile(ProfileNone),
		WithMaskChar("#"),
		WithMaskField("secret", "filled3"),
	)
	if err != nil {
		t.Fatalf("New(first): %v", err)
	}
	second, err := New(WithProfile(ProfileNone))
	if err != nil {
		t.Fatalf("New(second): %v", err)
	}

	input := map[string]string{"secret": "value", "plain": "visible"}
	maskedFirstAny, err := first.Mask(input)
	if err != nil {
		t.Fatalf("first.Mask: %v", err)
	}
	maskedSecondAny, err := second.Mask(input)
	if err != nil {
		t.Fatalf("second.Mask: %v", err)
	}

	maskedFirst := maskedFirstAny.(map[string]string)
	maskedSecond := maskedSecondAny.(map[string]string)
	if maskedFirst["secret"] != "###" {
		t.Fatalf("first secret = %q, want %q", maskedFirst["secret"], "###")
	}
	if maskedSecond["secret"] != "value" {
		t.Fatalf("second secret = %q, want original", maskedSecond["secret"])
	}
	if MaskChar() == "#" {
		t.Fatal("independent masker changed Default")
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name   string
		option Option
	}{
		{name: "nil option", option: nil},
		{name: "unknown profile", option: WithProfile(Profile("unknown"))},
		{name: "empty tag", option: WithTagName(" ")},
		{name: "empty mask char", option: WithMaskChar("")},
		{name: "empty field", option: WithMaskField("", "filled")},
		{name: "unknown field mask", option: WithMaskField("secret", "redcat")},
		{name: "nil function", option: WithMaskStringFunc("custom", nil)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.option)
			if !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("New() error = %v, want ErrInvalidOption", err)
			}
		})
	}
}

func TestRegisterMaskFieldRejectsUnknownMaskType(t *testing.T) {
	m, err := New(WithProfile(ProfileNone))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.RegisterMaskField("secret", "redcat"); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("RegisterMaskField error = %v, want ErrInvalidOption", err)
	}
}

func TestFreezeRejectsConfigurationChanges(t *testing.T) {
	m, err := New(WithProfile(ProfileNone))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.Freeze()

	if !m.Frozen() {
		t.Fatal("Frozen() = false, want true")
	}
	if err := m.SetMaskChar("#"); !errors.Is(err, ErrFrozen) {
		t.Fatalf("SetMaskChar error = %v, want ErrFrozen", err)
	}
	if err := m.RegisterMaskField("secret", "redact"); !errors.Is(err, ErrFrozen) {
		t.Fatalf("RegisterMaskField error = %v, want ErrFrozen", err)
	}
	if err := m.RegisterMaskStringFunc("custom", func(_, value string) (string, error) {
		return strings.ToUpper(value), nil
	}); !errors.Is(err, ErrFrozen) {
		t.Fatalf("RegisterMaskStringFunc error = %v, want ErrFrozen", err)
	}
}

func TestSecureProfileIsFrozen(t *testing.T) {
	m, err := New(WithProfile(ProfileSecure))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.Frozen() {
		t.Fatal("ProfileSecure instance is not frozen")
	}
	if err := m.RegisterMaskField("api_key", "preserveEnds(2,2)"); !errors.Is(err, ErrFrozen) {
		t.Fatalf("RegisterMaskField error = %v, want ErrFrozen", err)
	}
}

func TestNewCustomFunctions(t *testing.T) {
	m, err := New(
		WithProfile(ProfileNone),
		WithMaskStringFunc("upper", func(_, value string) (string, error) {
			return strings.ToUpper(value), nil
		}),
		WithMaskField("label", "upper"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	maskedAny, err := m.Mask(map[string]string{"label": "safe"})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if got := maskedAny.(map[string]string)["label"]; got != "SAFE" {
		t.Fatalf("label = %q, want SAFE", got)
	}
}
