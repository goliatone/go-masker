package masker

// SetMaskChar changes the character used for masking
// from default masker.
func SetMaskChar(s string) {
	Default.SetMaskChar(s)
}

// MaskChar returns the current character used for masking.
// from default masker.
func MaskChar() string {
	return Default.MaskChar()
}

// RegisterMaskField allows you to register a mask tag to be applied to the value of a struct field or map key that matches the fieldName.
// If a mask tag is set on the struct field, it will take precedence.
// from default masker.
func RegisterMaskField(fieldName, maskType string) {
	Default.RegisterMaskField(fieldName, maskType)
}

// RegisterMaskStringFunc registers a masking function for string values.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
// from default masker.
func RegisterMaskStringFunc(maskType string, maskFunc MaskStringFunc) {
	Default.RegisterMaskStringFunc(maskType, maskFunc)
}

// RegisterMaskIntFunc registers a masking function for int values.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
// from default masker.
func RegisterMaskIntFunc(maskType string, maskFunc MaskIntFunc) {
	Default.RegisterMaskIntFunc(maskType, maskFunc)
}

// RegisterMaskUintFunc registers a masking function for uint values.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
// from default masker.
func RegisterMaskUintFunc(maskType string, maskFunc MaskUintFunc) {
	Default.RegisterMaskUintFunc(maskType, maskFunc)
}

// RegisterMaskFloat64Func registers a masking function for float64 values.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
// from default masker.
func RegisterMaskFloat64Func(maskType string, maskFunc MaskFloat64Func) {
	Default.RegisterMaskFloat64Func(maskType, maskFunc)
}

// RegisterMaskAnyFunc registers a masking function that can be applied to any type.
// The function will be applied when the string set in the first argument is assigned as a tag to a field in the structure.
// from default masker.
func RegisterMaskAnyFunc(maskType string, maskFunc MaskAnyFunc) {
	Default.RegisterMaskAnyFunc(maskType, maskFunc)
}

// String masks the given argument string
// from default masker.
func String(tag, value string) (string, error) {
	return Default.String(tag, value)
}

// Int masks the given argument int
// from default masker.
func Int(tag string, value int) (int, error) {
	return Default.Int(tag, value)
}

// Uint masks the given argument int
// from default masker.
func Uint(tag string, value uint) (uint, error) {
	return Default.Uint(tag, value)
}

// Float64 masks the given argument float64
// from default masker.
func Float64(tag string, value float64) (float64, error) {
	return Default.Float64(tag, value)
}
