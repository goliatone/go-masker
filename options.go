package masker

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrFrozen is returned when configuration is changed after Freeze.
	ErrFrozen = errors.New("masker configuration is frozen")
	// ErrInvalidOption is returned when an option cannot produce a valid masker.
	ErrInvalidOption = errors.New("invalid masker option")
)

// Profile selects the preconfigured field rules installed by New.
type Profile string

const (
	// ProfileDefault preserves the package's historical field behavior.
	ProfileDefault Profile = "default"
	// ProfileSecure fully redacts credential-bearing fields with a fixed marker.
	ProfileSecure Profile = "secure"
	// ProfileNone installs no field-name rules. Built-in masking functions remain available.
	ProfileNone Profile = "none"
)

type config struct {
	tagName   string
	maskChar  string
	cache     bool
	profile   Profile
	fields    []fieldRegistration
	strings   []stringMaskRegistration
	uints     []uintMaskRegistration
	ints      []intMaskRegistration
	floats    []floatMaskRegistration
	anyValues []anyMaskRegistration
}

type fieldRegistration struct {
	fieldName string
	maskType  string
}

type stringMaskRegistration struct {
	maskType string
	fn       MaskStringFunc
}

type uintMaskRegistration struct {
	maskType string
	fn       MaskUintFunc
}

type intMaskRegistration struct {
	maskType string
	fn       MaskIntFunc
}

type floatMaskRegistration struct {
	maskType string
	fn       MaskFloat64Func
}

type anyMaskRegistration struct {
	maskType string
	fn       MaskAnyFunc
}

func defaultConfig() config {
	return config{
		tagName:  "mask",
		maskChar: "*",
		cache:    true,
		profile:  ProfileDefault,
	}
}

// Option configures a newly constructed Masker.
type Option func(*config) error

// WithProfile selects a set of preconfigured field rules.
func WithProfile(profile Profile) Option {
	return func(cfg *config) error {
		switch profile {
		case ProfileDefault, ProfileSecure, ProfileNone:
			cfg.profile = profile
			return nil
		default:
			return fmt.Errorf("%w: unknown profile %q", ErrInvalidOption, profile)
		}
	}
}

// WithTagName changes the struct tag used for masking rules.
func WithTagName(name string) Option {
	return func(cfg *config) error {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%w: tag name cannot be empty", ErrInvalidOption)
		}
		cfg.tagName = name
		return nil
	}
}

// WithMaskChar changes the character used by filled and preserve-ends masks.
func WithMaskChar(char string) Option {
	return func(cfg *config) error {
		if char == "" {
			return fmt.Errorf("%w: mask character cannot be empty", ErrInvalidOption)
		}
		cfg.maskChar = char
		return nil
	}
}

// WithCache enables or disables the wrapped masker's reflection cache.
func WithCache(enabled bool) Option {
	return func(cfg *config) error {
		cfg.cache = enabled
		return nil
	}
}

// WithMaskField registers a masking rule for a struct field or string map key.
func WithMaskField(fieldName, maskType string) Option {
	return func(cfg *config) error {
		if strings.TrimSpace(fieldName) == "" || strings.TrimSpace(maskType) == "" {
			return fmt.Errorf("%w: field name and mask type are required", ErrInvalidOption)
		}
		cfg.fields = append(cfg.fields, fieldRegistration{fieldName: fieldName, maskType: maskType})
		return nil
	}
}

// WithMaskStringFunc registers a custom string masking function.
func WithMaskStringFunc(maskType string, maskFunc MaskStringFunc) Option {
	return func(cfg *config) error {
		if strings.TrimSpace(maskType) == "" || maskFunc == nil {
			return fmt.Errorf("%w: string mask type and function are required", ErrInvalidOption)
		}
		cfg.strings = append(cfg.strings, stringMaskRegistration{maskType: maskType, fn: maskFunc})
		return nil
	}
}

// WithMaskUintFunc registers a custom uint masking function.
func WithMaskUintFunc(maskType string, maskFunc MaskUintFunc) Option {
	return func(cfg *config) error {
		if strings.TrimSpace(maskType) == "" || maskFunc == nil {
			return fmt.Errorf("%w: uint mask type and function are required", ErrInvalidOption)
		}
		cfg.uints = append(cfg.uints, uintMaskRegistration{maskType: maskType, fn: maskFunc})
		return nil
	}
}

// WithMaskIntFunc registers a custom int masking function.
func WithMaskIntFunc(maskType string, maskFunc MaskIntFunc) Option {
	return func(cfg *config) error {
		if strings.TrimSpace(maskType) == "" || maskFunc == nil {
			return fmt.Errorf("%w: int mask type and function are required", ErrInvalidOption)
		}
		cfg.ints = append(cfg.ints, intMaskRegistration{maskType: maskType, fn: maskFunc})
		return nil
	}
}

// WithMaskFloat64Func registers a custom float64 masking function.
func WithMaskFloat64Func(maskType string, maskFunc MaskFloat64Func) Option {
	return func(cfg *config) error {
		if strings.TrimSpace(maskType) == "" || maskFunc == nil {
			return fmt.Errorf("%w: float mask type and function are required", ErrInvalidOption)
		}
		cfg.floats = append(cfg.floats, floatMaskRegistration{maskType: maskType, fn: maskFunc})
		return nil
	}
}

// WithMaskAnyFunc registers a custom masking function for any supported value.
func WithMaskAnyFunc(maskType string, maskFunc MaskAnyFunc) Option {
	return func(cfg *config) error {
		if strings.TrimSpace(maskType) == "" || maskFunc == nil {
			return fmt.Errorf("%w: any mask type and function are required", ErrInvalidOption)
		}
		cfg.anyValues = append(cfg.anyValues, anyMaskRegistration{maskType: maskType, fn: maskFunc})
		return nil
	}
}
