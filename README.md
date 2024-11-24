# Go Masker

Simple package to mask sensitive data in Go structs. Wraps and extends [go-mask](https://github.com/showa-93/go-mask) with pre-configured rules and easier setup.

## Install

```bash
go get github.com/goliatone/go-masker
```

## Usage

Basic struct masking:

```go
type User struct {
    Username string
    Password string `mask:"filled4"`  // Will mask with 4 chars
    APIKey   string `mask:"filled32"` // Will mask with 32 chars
}

user := User{
    Username: "john",
    Password: "secret123",
    APIKey:   "1234567890",
}

// Using default masker
masked, err := masker.Mask(user)

// Output:
// {
//   "username": "john",
//   "password": "****",
//   "api_key": "********************************"
// }
```

Custom masking:

```go
// Create custom masker
m := masker.New()

// Register custom field mask
m.RegisterMaskField("api_key", "filled32")

// Register custom masking function
m.RegisterMaskStringFunc("custom", func(arg, value string) (string, error) {
    return strings.Repeat("*", len(value)), nil
})
```

## Mask Types

- `hash`: SHA1 hash of the string
- `fixed`: Fixed 8 char mask
- `filled`: Mask with specified length (e.g., `filled4`, `filled32`)
- `random`: Random number for numeric types
- `zero`: Sets to zero value

## Default Masked Fields

These come pre-configured:
- Password/password: 4 chars
- SigningKey/signing_key: 32 chars
- Authorization/authorization: 32 chars

## Configuration

```go
m := masker.New()

// Change tag name (default: "mask")
m.SetTagName("secure")

// Change mask character (default: "*")
m.SetMaskChar("#")

// Toggle type caching
m.Cache(false)
```

## Supported Types

- string (MaskStringFunc)
- uint (MaskUintFunc)
- int (MaskIntFunc)
- float64 (MaskFloat64Func)
- any (MaskAnyFunc)

## Features

- Pre-configured for common sensitive fields
- Custom masking functions
- Field-based masking
- Thread safe
- Type info caching
- Supports multiple data types

## License

MIT

Copyright (c) 2024 goliatone
