package template

import (
	"strconv"
	"strings"
	"unicode"

	pcre "github.com/zmap/zgrab2/lib/pcre"
)

type funcFn func(*pcre.Matcher, ...string) string

var builtinFuncs = map[string]funcFn{
	"SUBST": subst,
	"P":     printable,
	"I":     asInt,
}

func subst(match *pcre.Matcher, args ...string) string {
	if len(args) >= 3 {
		if g, err := match.NamedString(args[0]); g != "" && err == nil {
			return strings.ReplaceAll(g, args[1], args[2])
		}
	}
	return ""
}

func printable(match *pcre.Matcher, args ...string) (result string) {
	if len(args) >= 1 {
		if g, err := match.NamedString(args[0]); g != "" && err == nil {
			for _, rune := range g {
				if unicode.IsPrint(rune) {
					result += string(rune)
				}
			}
		}
	}
	return result
}

func asInt(match *pcre.Matcher, args ...string) string {
	var n uint64
	if len(args) >= 2 {
		if g, err := match.NamedString(args[0]); g != "" && err == nil {
			switch args[1] {
			case ">":
				n = asIntBE(g)
			case "<":
				n = asIntLE(g)
			}
		}
	}
	return strconv.FormatUint(n, 10)
}

func asIntBE(s string) (result uint64) {
	for i := 0; i < len(s); i++ {
		result = (result << 8) | uint64(s[i])
	}
	return result
}

func asIntLE(s string) (result uint64) {
	for i := len(s) - 1; i >= 0; i-- {
		result = (result << 8) | uint64(s[i])
	}
	return result
}
