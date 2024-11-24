package masker

import (
	"github.com/showa-93/go-mask"
)

var Default *Masker

type (
	MaskStringFunc  func(arg string, value string) (string, error)
	MaskUintFunc    func(arg string, value uint) (uint, error)
	MaskIntFunc     func(arg string, value int) (int, error)
	MaskFloat64Func func(arg string, value float64) (float64, error)
	MaskAnyFunc     func(arg string, value any) (any, error)
)

type Masker struct {
	masker *mask.Masker
}

func init() {
	msk := mask.NewMasker()
	msk.RegisterMaskStringFunc(mask.MaskTypeHash, msk.MaskHashString)
	msk.RegisterMaskStringFunc(mask.MaskTypeFixed, msk.MaskFixedString)
	msk.RegisterMaskStringFunc(mask.MaskTypeFilled, msk.MaskFilledString)

	msk.RegisterMaskIntFunc(mask.MaskTypeRandom, msk.MaskRandomInt)
	msk.RegisterMaskFloat64Func(mask.MaskTypeRandom, msk.MaskRandomFloat64)
	msk.RegisterMaskAnyFunc(mask.MaskTypeZero, msk.MaskZero)

	msk.RegisterMaskField("Password", "filled4")
	msk.RegisterMaskField("password", "filled4")

	msk.RegisterMaskField("SigningKey", "filled32")
	msk.RegisterMaskField("signing_key", "filled32")

	msk.RegisterMaskField("Authorization", "filled32")
	msk.RegisterMaskField("authorization", "filled32")

	Default = &Masker{masker: msk}
}

func Mask[T any](target T) (ret T, err error) {
	return mask.Mask(target)
}

// SetTagName allows you to change the tag name from "mask" to something else.
func (m *Masker) SetTagName(s string) {
	m.masker.SetTagName(s)
}

// SetMaskChar changes the character used for masking
func (m *Masker) SetMaskChar(s string) {
	m.masker.SetMaskChar(s)
}

// Cache can be toggled to cache the type information of the struct.
// default true
func (m *Masker) Cache(enable bool) {
	m.masker.Cache(enable)
}

// MaskChar returns the current character used for masking.
func (m *Masker) MaskChar() string {
	return m.masker.MaskChar()
}

// RegisterMaskStringFunc registers a masking function for string values.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
func (m *Masker) RegisterMaskStringFunc(maskType string, maskFunc MaskStringFunc) {
	v := func(arg string, value string) (string, error) {
		return maskFunc(arg, value)
	}
	m.masker.RegisterMaskStringFunc(maskType, v)
}

// RegisterMaskUintFunc registers a masking function for uint values.
// The function will be applied when the uint slice set in the first argument is assigned as a tag to a field in the structure.
func (m *Masker) RegisterMaskUintFunc(maskType string, maskFunc MaskUintFunc) {
	v := func(arg string, value uint) (uint, error) {
		return maskFunc(arg, value)
	}
	m.masker.RegisterMaskUintFunc(maskType, v)
}

// RegisterMaskIntFunc registers a masking function for int values.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
func (m *Masker) RegisterMaskIntFunc(maskType string, maskFunc MaskIntFunc) {
	v := func(arg string, value int) (int, error) {
		return maskFunc(arg, value)
	}
	m.masker.RegisterMaskIntFunc(maskType, v)
}

// RegisterMaskFloat64Func registers a masking function for float64 values.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
func (m *Masker) RegisterMaskFloat64Func(maskType string, maskFunc MaskFloat64Func) {
	v := func(arg string, value float64) (float64, error) {
		return maskFunc(arg, value)
	}
	m.masker.RegisterMaskFloat64Func(maskType, v)
}

// RegisterMaskAnyFunc registers a masking function that can be applied to any type.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
func (m *Masker) RegisterMaskAnyFunc(maskType string, maskFunc MaskAnyFunc) {
	v := func(arg string, value any) (any, error) {
		return maskFunc(arg, value)
	}
	m.masker.RegisterMaskAnyFunc(maskType, v)
}

// RegisterMaskField allows you to register a mask tag to be applied to the value of a struct field or map key that matches the fieldName.
// If a mask tag is set on the struct field, it will take precedence.
func (m *Masker) RegisterMaskField(fieldName, maskType string) {
	m.masker.RegisterMaskField(fieldName, maskType)
}

// String masks the given argument string
func (m *Masker) String(tag, value string) (string, error) {
	return m.masker.String(tag, value)
}

// Uint masks the given argument uint
func (m *Masker) Uint(tag string, value uint) (uint, error) {
	return m.masker.Uint(tag, value)
}

// Int masks the given argument int
func (m *Masker) Int(tag string, value int) (int, error) {
	return m.masker.Int(tag, value)
}

// Float64 masks the given argument float64
func (m *Masker) Float64(tag string, value float64) (float64, error) {
	return m.masker.Float64(tag, value)
}

// MaskFilledString masks the string length of the value with the same length.
// If you pass a number like "2" to arg, it masks with the length of the number.(**)
func (m *Masker) MaskFilledString(arg, value string) (string, error) {
	return m.masker.MaskFilledString(arg, value)
}

// MaskFixedString masks with a fixed length (8 characters).
func (m *Masker) MaskFixedString(arg, value string) (string, error) {
	return m.masker.MaskFixedString(arg, value)
}

// MaskHashString masks and hashes (sha1) a string.
func (m *Masker) MaskHashString(arg, value string) (string, error) {
	return m.masker.MaskHashString(arg, value)
}

// MaskRandomInt converts an integer (int) into a random number.
// For example, if you pass "100" as the arg, it sets a random number in the range of 0-99.
func (m *Masker) MaskRandomInt(arg string, value int) (int, error) {
	return m.masker.MaskRandomInt(arg, value)
}

// MaskRandomFloat64 converts a float64 to a random number.
// For example, if you pass "100.3" to arg, it sets a random number in the range of 0.000 to 99.999.
func (m *Masker) MaskRandomFloat64(arg string, value float64) (float64, error) {
	return m.masker.MaskRandomFloat64(arg, value)
}

// MaskZero converts the value to its type's zero value.
func (m *Masker) MaskZero(arg string, value any) (any, error) {
	return m.masker.MaskZero(arg, value)
}

// Mask returns an object with the mask applied to any given object.
// The function's argument can accept any type, including pointer, map, and slice types, in addition to struct.
func (m *Masker) Mask(target any) (ret any, err error) {
	return m.masker.Mask(target)
}
