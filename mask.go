package masker

import (
	"fmt"
	"strings"
	"sync"

	"github.com/showa-93/go-mask"
)

// Default backs the package-level compatibility helpers. New integrations should
// construct and freeze an independent Masker instead of mutating Default.
var Default = mustNew()

type (
	MaskStringFunc  = mask.MaskStringFunc
	MaskUintFunc    = mask.MaskUintFunc
	MaskIntFunc     = mask.MaskIntFunc
	MaskFloat64Func = mask.MaskFloat64Func
	MaskAnyFunc     = mask.MaskAnyFunc
)

// Masker wraps go-mask with independent configuration and a concurrency-safe
// lifecycle. Configuration methods take an exclusive lock; masking is safe for
// concurrent use. Freeze prevents later configuration changes.
type Masker struct {
	mu        sync.RWMutex
	masker    *mask.Masker
	cache     bool
	maskChar  string
	frozen    bool
	maskTypes map[string]struct{}
}

// New constructs an independent masker with built-in functions and the default
// field profile. Options are applied before the instance becomes visible.
func New(options ...Option) (*Masker, error) {
	cfg := defaultConfig()
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: option cannot be nil", ErrInvalidOption)
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}

	underlying := mask.NewMasker()
	underlying.SetTagName(cfg.tagName)
	underlying.SetMaskChar(cfg.maskChar)
	underlying.Cache(cfg.cache)

	m := &Masker{
		masker:    underlying,
		cache:     cfg.cache,
		maskChar:  cfg.maskChar,
		maskTypes: make(map[string]struct{}),
	}
	m.registerBuiltins()

	for _, registration := range cfg.strings {
		m.registerMaskStringFunc(registration.maskType, registration.fn)
	}
	for _, registration := range cfg.uints {
		m.registerMaskUintFunc(registration.maskType, registration.fn)
	}
	for _, registration := range cfg.ints {
		m.registerMaskIntFunc(registration.maskType, registration.fn)
	}
	for _, registration := range cfg.floats {
		m.registerMaskFloat64Func(registration.maskType, registration.fn)
	}
	for _, registration := range cfg.anyValues {
		m.registerMaskAnyFunc(registration.maskType, registration.fn)
	}
	if cfg.profile == ProfileDefault {
		m.registerProfile(ProfileDefault)
	}
	for _, registration := range cfg.fields {
		if !m.supportsMaskType(registration.maskType) {
			return nil, fmt.Errorf("%w: unknown mask type %q for field %q", ErrInvalidOption, registration.maskType, registration.fieldName)
		}
		m.registerMaskField(registration.fieldName, registration.maskType)
	}
	if cfg.profile == ProfileSecure {
		m.enforceSecureRedaction()
		m.registerProfile(ProfileSecure)
		m.frozen = true
	}

	return m, nil
}

// NewSecure constructs and freezes an independent security-profiled masker.
// Callers can supply additional options to override defaults before freezing.
func NewSecure(options ...Option) (*Masker, error) {
	secureOptions := make([]Option, 0, len(options)+2)
	secureOptions = append(secureOptions, options...)
	secureOptions = append(secureOptions, WithProfile(ProfileSecure), WithCache(false))
	m, err := New(secureOptions...)
	if err != nil {
		return nil, err
	}
	return m.Freeze(), nil
}

func mustNew(options ...Option) *Masker {
	m, err := New(options...)
	if err != nil {
		panic(err)
	}
	return m
}

func (m *Masker) registerBuiltins() {
	m.registerMaskStringFunc(mask.MaskTypeHash, m.masker.MaskHashString)
	m.registerMaskStringFunc(mask.MaskTypeFixed, m.masker.MaskFixedString)
	m.registerMaskStringFunc(mask.MaskTypeFilled, m.masker.MaskFilledString)
	m.registerMaskStringFunc(MaskTypePreserveEnds, func(arg, value string) (string, error) {
		return maskPreserveEnds(m.maskChar, arg, value)
	})

	m.registerMaskIntFunc(mask.MaskTypeRandom, m.masker.MaskRandomInt)
	m.registerMaskFloat64Func(mask.MaskTypeRandom, m.masker.MaskRandomFloat64)
	m.registerMaskAnyFunc(mask.MaskTypeZero, m.masker.MaskZero)
	m.registerMaskAnyFunc(MaskTypeRedact, MaskRedactAny)
}

func (m *Masker) enforceSecureRedaction() {
	// String fields and string collections use the string registry directly;
	// other structured values use the any-value registry.
	m.registerMaskStringFunc(MaskTypeRedact, MaskRedact)
	m.registerMaskAnyFunc(MaskTypeRedact, MaskRedactAny)
}

func (m *Masker) registerMaskStringFunc(maskType string, fn MaskStringFunc) {
	m.masker.RegisterMaskStringFunc(maskType, fn)
	m.maskTypes[maskType] = struct{}{}
}

func (m *Masker) registerMaskUintFunc(maskType string, fn MaskUintFunc) {
	m.masker.RegisterMaskUintFunc(maskType, fn)
	m.maskTypes[maskType] = struct{}{}
}

func (m *Masker) registerMaskIntFunc(maskType string, fn MaskIntFunc) {
	m.masker.RegisterMaskIntFunc(maskType, fn)
	m.maskTypes[maskType] = struct{}{}
}

func (m *Masker) registerMaskFloat64Func(maskType string, fn MaskFloat64Func) {
	m.masker.RegisterMaskFloat64Func(maskType, fn)
	m.maskTypes[maskType] = struct{}{}
}

func (m *Masker) registerMaskAnyFunc(maskType string, fn MaskAnyFunc) {
	m.masker.RegisterMaskAnyFunc(maskType, fn)
	m.maskTypes[maskType] = struct{}{}
}

func (m *Masker) supportsMaskType(maskType string) bool {
	for registered := range m.maskTypes {
		if strings.HasPrefix(maskType, registered) {
			return true
		}
	}
	return false
}

func (m *Masker) registerProfile(profile Profile) {
	switch profile {
	case ProfileDefault:
		for fieldName, maskType := range defaultProfileFields() {
			m.registerMaskField(fieldName, maskType)
		}
	case ProfileSecure:
		for fieldName, maskType := range secureProfileFields() {
			m.registerMaskField(fieldName, maskType)
		}
	case ProfileNone:
		return
	}
}

func defaultProfileFields() map[string]string {
	return map[string]string{
		"password":      "filled4",
		"signing_key":   "filled32",
		"authorization": "filled32",
		"token":         "preserveEnds(4,4)",
		"access_token":  "preserveEnds(4,4)",
		"refresh_token": "preserveEnds(4,4)",
		"credit_card":   "preserveEnds(4,4)",
		"api_key":       "preserveEnds(2,2)",
		"APIKey":        "preserveEnds(2,2)",
		"client_secret": "preserveEnds(2,2)",
	}
}

// Freeze prevents subsequent configuration changes. Masking remains available.
func (m *Masker) Freeze() *Masker {
	m.mu.Lock()
	m.frozen = true
	m.mu.Unlock()
	return m
}

// Frozen reports whether configuration has been frozen.
func (m *Masker) Frozen() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.frozen
}

func (m *Masker) ensureMutable() error {
	if m.frozen {
		return ErrFrozen
	}
	return nil
}

func Mask[T any](target T) (ret T, err error) {
	var value any
	value, err = Default.Mask(target)
	if err != nil {
		return ret, err
	}
	if value == nil {
		return ret, nil
	}
	typed, ok := value.(T)
	if !ok {
		return ret, fmt.Errorf("mask result type %T does not match input type", value)
	}
	return typed, nil
}

// SetTagName changes the struct tag name used for masking.
func (m *Masker) SetTagName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: tag name cannot be empty", ErrInvalidOption)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	m.masker.SetTagName(name)
	return nil
}

// SetMaskChar changes the character used for masking.
func (m *Masker) SetMaskChar(char string) error {
	if char == "" {
		return fmt.Errorf("%w: mask character cannot be empty", ErrInvalidOption)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	m.maskChar = char
	m.masker.SetMaskChar(char)
	return nil
}

// Cache toggles the wrapped masker's reflection cache.
func (m *Masker) Cache(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	m.cache = enabled
	m.masker.Cache(enabled)
	return nil
}

// MaskChar returns the current mask character.
func (m *Masker) MaskChar() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maskChar
}

func (m *Masker) RegisterMaskStringFunc(maskType string, maskFunc MaskStringFunc) error {
	if strings.TrimSpace(maskType) == "" || maskFunc == nil {
		return fmt.Errorf("%w: string mask type and function are required", ErrInvalidOption)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	m.registerMaskStringFunc(maskType, maskFunc)
	return nil
}

func (m *Masker) RegisterMaskUintFunc(maskType string, maskFunc MaskUintFunc) error {
	if strings.TrimSpace(maskType) == "" || maskFunc == nil {
		return fmt.Errorf("%w: uint mask type and function are required", ErrInvalidOption)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	m.registerMaskUintFunc(maskType, maskFunc)
	return nil
}

func (m *Masker) RegisterMaskIntFunc(maskType string, maskFunc MaskIntFunc) error {
	if strings.TrimSpace(maskType) == "" || maskFunc == nil {
		return fmt.Errorf("%w: int mask type and function are required", ErrInvalidOption)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	m.registerMaskIntFunc(maskType, maskFunc)
	return nil
}

func (m *Masker) RegisterMaskFloat64Func(maskType string, maskFunc MaskFloat64Func) error {
	if strings.TrimSpace(maskType) == "" || maskFunc == nil {
		return fmt.Errorf("%w: float mask type and function are required", ErrInvalidOption)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	m.registerMaskFloat64Func(maskType, maskFunc)
	return nil
}

func (m *Masker) RegisterMaskAnyFunc(maskType string, maskFunc MaskAnyFunc) error {
	if strings.TrimSpace(maskType) == "" || maskFunc == nil {
		return fmt.Errorf("%w: any mask type and function are required", ErrInvalidOption)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	m.registerMaskAnyFunc(maskType, maskFunc)
	return nil
}

// RegisterMaskField registers a rule for common naming variants of fieldName.
func (m *Masker) RegisterMaskField(fieldName, maskType string) error {
	if strings.TrimSpace(fieldName) == "" || strings.TrimSpace(maskType) == "" {
		return fmt.Errorf("%w: field name and mask type are required", ErrInvalidOption)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMutable(); err != nil {
		return err
	}
	if !m.supportsMaskType(maskType) {
		return fmt.Errorf("%w: unknown mask type %q for field %q", ErrInvalidOption, maskType, fieldName)
	}
	m.registerMaskField(fieldName, maskType)
	return nil
}

func (m *Masker) registerMaskField(fieldName, maskType string) {
	for _, alias := range fieldAliases(fieldName) {
		m.masker.RegisterMaskField(alias, maskType)
	}
}

func (m *Masker) String(tag, value string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.String(tag, value)
}

func (m *Masker) Uint(tag string, value uint) (uint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.Uint(tag, value)
}

func (m *Masker) Int(tag string, value int) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.Int(tag, value)
}

func (m *Masker) Float64(tag string, value float64) (float64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.Float64(tag, value)
}

func (m *Masker) MaskFilledString(arg, value string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.MaskFilledString(arg, value)
}

func (m *Masker) MaskFixedString(arg, value string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.MaskFixedString(arg, value)
}

func (m *Masker) MaskHashString(arg, value string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.MaskHashString(arg, value)
}

func (m *Masker) MaskRandomInt(arg string, value int) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.MaskRandomInt(arg, value)
}

func (m *Masker) MaskRandomFloat64(arg string, value float64) (float64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.MaskRandomFloat64(arg, value)
}

func (m *Masker) MaskZero(arg string, value any) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.masker.MaskZero(arg, value)
}

// Mask returns a deep masked copy. Calls are serialized when the wrapped
// dependency's reflection cache is enabled because that cache reuses mutable
// destinations. Cache-disabled calls may execute concurrently.
func (m *Masker) Mask(target any) (any, error) {
	if target == nil {
		return nil, nil
	}

	m.mu.RLock()
	if !m.cache {
		defer m.mu.RUnlock()
		return m.masker.Mask(target)
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.masker.Mask(target)
}
