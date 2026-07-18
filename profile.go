package masker

import (
	"strings"
	"unicode"
)

func secureProfileFields() map[string]string {
	fields := make(map[string]string)
	for _, fieldName := range []string{
		"password",
		"passphrase",
		"secret",
		"client_secret",
		"signing_key",
		"private_key",
		"authorization",
		"proxy_authorization",
		"token",
		"access_token",
		"refresh_token",
		"id_token",
		"api_key",
		"x_api_key",
		"credential",
		"credentials",
		"cookie",
		"set_cookie",
		"credit_card",
	} {
		fields[fieldName] = MaskTypeRedact
	}
	return fields
}

func fieldAliases(name string) []string {
	words := identifierWords(name)
	if len(words) == 0 {
		return nil
	}

	aliases := map[string]struct{}{
		name:                                      {},
		strings.ToLower(name):                     {},
		strings.ToUpper(name):                     {},
		strings.Join(words, "_"):                  {},
		strings.Join(words, "-"):                  {},
		strings.Join(words, ""):                   {},
		strings.ToUpper(strings.Join(words, "_")): {},
		strings.ToUpper(strings.Join(words, "-")): {},
	}

	pascal := make([]string, len(words))
	for i, word := range words {
		pascal[i] = titleIdentifierWord(word)
	}
	aliases[strings.Join(pascal, "")] = struct{}{}
	aliases[strings.Join(pascal, "-")] = struct{}{}
	pascal[0] = words[0]
	aliases[strings.Join(pascal, "")] = struct{}{}

	result := make([]string, 0, len(aliases))
	for alias := range aliases {
		if alias != "" {
			result = append(result, alias)
		}
	}
	return result
}

func identifierWords(name string) []string {
	var words []string
	var current []rune
	runes := []rune(strings.TrimSpace(name))
	flush := func() {
		if len(current) == 0 {
			return
		}
		words = append(words, strings.ToLower(string(current)))
		current = current[:0]
	}

	for i, r := range runes {
		if r == '_' || r == '-' || r == ' ' || r == '.' {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(current) > 0 {
			previous := runes[i-1]
			nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(previous) || unicode.IsDigit(previous) || nextIsLower {
				flush()
			}
		}
		current = append(current, r)
	}
	flush()
	return words
}

func titleIdentifierWord(word string) string {
	switch word {
	case "api", "http", "https", "id", "ip", "jwt", "oauth", "tls", "url", "uuid":
		return strings.ToUpper(word)
	}
	runes := []rune(word)
	if len(runes) == 0 {
		return ""
	}
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
