package template

import (
	"strconv"
	"strings"

	pcre "github.com/zmap/zgrab2/lib/pcre"
)

type Template []Token

type Token struct {
	kind  tokenKind
	value string
	args  []string
}

type tokenKind int

const (
	tokenTerm  tokenKind = iota // Terminal token contains a literal string value.
	tokenGroup                  // Group token references a capturing group, example: $1, $2.
	tokenFunc                   // Function token, example: $SUBST(...)
)

func Term(s string) Token                    { return Token{kind: tokenTerm, value: s} }
func Group(index string) Token               { return Token{kind: tokenGroup, value: index} }
func Func(name string, args ...string) Token { return Token{kind: tokenFunc, value: name, args: args} }

func (tmpl Template) Render(match *pcre.Matcher) string {
	var b strings.Builder
	for _, token := range tmpl {
		res := token.Render(match)
		b.WriteString(res)
	}
	return b.String()
}

func (token Token) Render(match *pcre.Matcher) string {

	switch token.kind {
	case tokenTerm:
		return token.value
	case tokenGroup:
		return token.renderGroup(match)
	case tokenFunc:
		return token.renderFunc(match)
	}
	return ""
}

func (token Token) renderGroup(match *pcre.Matcher) string {
	ind, _ := strconv.Atoi(token.value)
	if g := match.GroupString(ind); g != "" {
		return g
	}
	return ""
}

func (token Token) renderFunc(match *pcre.Matcher) string {
	if fn, found := builtinFuncs[token.value]; found {
		return fn(match, token.args...)
	}
	return ""
}
