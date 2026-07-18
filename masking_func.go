package masker

import (
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaskTypePreserveEnds = "preserveEnds"
	MaskTypeRedact       = "redact"
	RedactedValue        = "[REDACTED]"
)

// MaskRedact replaces any non-empty string with a fixed marker that does not
// disclose the original value or its length.
func MaskRedact(_ string, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return RedactedValue, nil
}

// MaskRedactAny replaces strings and byte slices with RedactedValue and
// returns the zero value for other types. The returned value retains the input
// type so reflection-based struct masking remains assignable.
func MaskRedactAny(_ string, value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	rv := reflect.ValueOf(value)
	redacted := reflect.New(rv.Type()).Elem()
	switch rv.Kind() {
	case reflect.String:
		if rv.Len() == 0 {
			return value, nil
		}
		redacted.SetString(RedactedValue)
	case reflect.Slice:
		if rv.IsNil() || rv.Len() == 0 {
			return value, nil
		}
		switch rv.Type().Elem().Kind() {
		case reflect.Uint8:
			redacted.SetBytes([]byte(RedactedValue))
		case reflect.String:
			redacted.Set(reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len()))
			for i := 0; i < rv.Len(); i++ {
				redacted.Index(i).SetString(RedactedValue)
			}
		}
	case reflect.Array:
		if rv.Type().Elem().Kind() == reflect.String {
			for i := 0; i < rv.Len(); i++ {
				redacted.Index(i).SetString(RedactedValue)
			}
		}
	default:
		// The zero value is the safest type-preserving representation.
	}
	return redacted.Interface(), nil
}

func MaskPreserveEnds(arg string, value string) (string, error) {
	return maskPreserveEnds("*", arg, value)
}

func maskPreserveEnds(maskChar, arg, value string) (string, error) {
	if value == "" {
		return "", nil
	}

	var start, end int

	start, end = 3, 3

	openIdx := strings.Index(arg, "(")
	closeIdx := strings.Index(arg, ")")

	if openIdx >= 0 && closeIdx > openIdx {
		parts := strings.Split(arg[openIdx+1:closeIdx], ",")
		if len(parts) >= 2 {
			if s, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
				start = s
			}
			if e, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
				end = e
			}
		}
	}

	runeCount := utf8.RuneCountInString(value)
	if start < 0 {
		start = 0
	}
	if end < 0 {
		end = 0
	}
	if start > runeCount {
		start = runeCount
	}
	if end > runeCount {
		end = runeCount
	}

	if start >= runeCount || end >= runeCount || start > runeCount-end {
		if runeCount <= 3 {
			return strings.Repeat(maskChar, runeCount), nil
		}
		start = 1
		end = 1
	}

	runes := []rune(value)

	var sb strings.Builder
	sb.WriteString(string(runes[:start]))

	maskLength := runeCount - start - end
	sb.WriteString(strings.Repeat(maskChar, maskLength))

	sb.WriteString(string(runes[runeCount-end:]))

	return sb.String(), nil
}
