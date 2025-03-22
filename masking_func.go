package masker

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/showa-93/go-mask"
)

const MaskTypePreserveEnds = "preserveEnds"

func MaskPreserveEnds(arg string, value string) (string, error) {
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

	if start+end >= runeCount {
		if runeCount <= 3 {
			return strings.Repeat(mask.MaskChar(), runeCount), nil
		}
		start = 1
		end = 1
	}

	runes := []rune(value)

	var sb strings.Builder
	sb.WriteString(string(runes[:start]))

	maskLength := runeCount - start - end
	sb.WriteString(strings.Repeat(mask.MaskChar(), maskLength))

	sb.WriteString(string(runes[runeCount-end:]))

	return sb.String(), nil
}
