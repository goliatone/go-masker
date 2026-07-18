# Go Masker

`go-masker` creates masked copies of Go structs, maps, slices, pointers, and scalar values. It wraps `github.com/showa-93/go-mask` with independent instances, predefined field profiles, fixed redaction, and configure-then-freeze semantics.

## Install

```bash
go get github.com/goliatone/go-masker
```

## Security model

Masking is most reliable for structured data with known fields or map keys. It is not a general secret scanner and cannot guarantee detection of credentials embedded in arbitrary prose.

- Use `NewSecure` for credential-bearing output.
- Omit untrusted free-form strings unless a dedicated sanitizer makes them safe.
- Treat masking as defense in depth after field selection and allowlisting.
- If masking returns an error, do not fall back to the original value.

The secure profile replaces credentials with the fixed marker `[REDACTED]`. It does not preserve token fragments or disclose their original length.

## Secure instance

```go
m, err := masker.NewSecure()
if err != nil {
    return err
}

masked, err := m.Mask(map[string]any{
    "clientSecret": "secret-value",
    "visible":      "safe-value",
})
if err != nil {
    return err // fail closed; do not use the input as fallback
}
```

`NewSecure` disables the upstream reflection cache and freezes the instance. Configure it entirely through options:

```go
m, err := masker.NewSecure(
    masker.WithTagName("mask"),
    masker.WithMaskChar("#"),
    masker.WithMaskField("tenantCredential", masker.MaskTypeRedact),
)
```

Security-sensitive aliases include common snake_case, kebab-case, camelCase, PascalCase, and header-style names for passwords, secrets, tokens, authorization values, cookies, signing/private keys, credentials, API keys, and credit cards.

## General instances

`New` creates an independent configurable instance with the compatibility profile:

```go
m, err := masker.New(
    masker.WithProfile(masker.ProfileDefault),
    masker.WithCache(false),
)
if err != nil {
    return err
}

if err := m.RegisterMaskField("account_id", "preserveEnds(2,2)"); err != nil {
    return err
}
m.Freeze()
```

Available profiles:

- `ProfileDefault`: compatibility rules, including partial token and identifier masking.
- `ProfileSecure`: fixed full redaction for credential fields.
- `ProfileNone`: no field-name rules; built-in masking functions remain registered.

Options can configure:

- tag name and mask character;
- cache behavior;
- field rules;
- custom string, integer, unsigned integer, float, and any-value functions.

Invalid options cause `New` to return `ErrInvalidOption` without returning a partial instance. Configuration after `Freeze` returns `ErrFrozen`.

## Struct tags and custom rules

Struct tags take precedence over field-name profiles:

```go
type Customer struct {
    Name       string
    Password   string
    Identifier string `mask:"preserveEnds(2,2)"`
}
```

Custom functions can be registered as options or before freezing:

```go
m, err := masker.New(
    masker.WithProfile(masker.ProfileNone),
    masker.WithMaskStringFunc("custom", func(arg, value string) (string, error) {
        return "[CUSTOM]", nil
    }),
    masker.WithMaskField("label", "custom"),
)
```

## Mask types

- `redact`: fixed `[REDACTED]` output for strings and bytes; type-safe zero values for other sensitive values.
- `filled`: repeated mask character, optionally with a requested length such as `filled4`.
- `fixed`: fixed eight-character mask.
- `preserveEnds(start,end)`: preserves selected string ends; use only for non-secret identifiers.
- `hash`: SHA-1 representation inherited for compatibility; not suitable as credential protection.
- `random`: random numeric replacement.
- `zero`: the value's zero value.

## Concurrency

Configuration methods and masking are synchronized. Freeze an instance before sharing it.

- Cache-disabled instances allow concurrent mask operations and are recommended for security-sensitive output paths.
- Cache-enabled operations are serialized because the wrapped dependency reuses mutable reflection destinations.
- Independent instances do not share configuration.
- The mutable package-level `Default` exists for compatibility and should not be used as an application-wide configuration surface by libraries.

## Compatibility helpers

Package functions such as `Mask`, `RegisterMaskField`, and `SetMaskChar` delegate to `Default`. New integrations should prefer an independent instance:

```go
masked, err := masker.Mask(value) // compatibility path
```

## License

MIT

Copyright (c) 2024 goliatone
