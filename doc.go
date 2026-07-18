// Package masker creates masked copies of structured Go values.
//
// For credential-bearing output, construct a dedicated frozen secure instance:
//
//	m, err := masker.NewSecure(
//		masker.WithMaskField("tenantCredential", masker.MaskTypeRedact),
//	)
//	if err != nil {
//		return err
//	}
//	masked, err := m.Mask(value)
//
// New creates a general independent instance. Configure it with options or
// registration methods, then call Freeze before sharing it across goroutines.
// Package-level helpers delegate to the mutable Default instance and are kept
// for compatibility; libraries should not use Default as global configuration.
//
// The secure profile fully replaces recognized credential fields with a fixed
// marker. Preserve-ends and hash rules remain available for explicit non-secret
// use cases. Masking is field-based and does not reliably discover secrets in
// arbitrary prose, so callers should omit untrusted free-form strings and must
// not fall back to raw values when masking fails.
//
// Cache-disabled Mask calls can run concurrently. Cache-enabled Mask calls are
// serialized to contain mutable reflection destinations in the wrapped
// dependency. Configuration methods are synchronized, and Freeze prevents
// subsequent changes.
package masker
