// Package masker provides a flexible data masking system for Go applications,
// allowing you to protect sensitive information in various data types.
//
// The package wraps and extends github.com/showa-93/go-mask functionality,
// providing additional convenience methods and pre-configured masking rules
// for common sensitive fields.
//
// By default, the package initializes with common masking rules for sensitive fields:
//   - Password/password: 4 character mask
//   - SigningKey/signing_key: 32 character mask
//   - Authorization/authorization: 32 character mask
//
// Basic usage with the default masker:
//
//	type User struct {
//		Username string
//		Password string `mask:"filled4"`
//	}
//
//	user := User{
//		Username: "john",
//		Password: "secret123",
//	}
//
//	masked, err := masker.Mask(user)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Available Masking Types:
//   - hash: Masks and hashes (sha1) a string
//   - fixed: Masks with a fixed length (8 characters)
//   - filled: Masks the entire string or with specified length
//   - random: For numeric types, generates random values within range
//   - zero: Sets the field to its zero value
//
// Custom Masking:
//
//	m := &Masker{...}
//	m.RegisterMaskStringFunc("custom", func(arg, value string) (string, error) {
//		return strings.Repeat("*", len(value)), nil
//	})
//
// Field Registration:
//
//	m := &Masker{...}
//	m.RegisterMaskField("api_key", "filled32")
//
// Configuration:
//
// The package supports various configuration options:
//
//	m.SetTagName("mask")      // Change the struct tag name
//	m.SetMaskChar("*")        // Change the masking character
//	m.Cache(true)             // Enable/disable type information caching
//
// Supported Types:
//   - string (MaskStringFunc)
//   - uint (MaskUintFunc)
//   - int (MaskIntFunc)
//   - float64 (MaskFloat64Func)
//   - any (MaskAnyFunc)
//
// Thread Safety:
//
// The package maintains a global Default masker instance that is safe for
// concurrent use after initialization. Custom masker instances should be
// handled with appropriate synchronization if modified after initialization.
//
// Performance:
//
// Type information caching is enabled by default to improve performance.
// For dynamic structures where fields change frequently, caching can be
// disabled using the Cache(false) method.
//
// For additional information and updates, visit:
// https://github.com/goliatone/go-masker
package masker
