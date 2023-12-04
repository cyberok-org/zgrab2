package nmap

import (
	"fmt"
	"strings"
	"unicode/utf8"

	pcre "github.com/zmap/zgrab2/lib/pcre"
)

type Matcher struct {
	Info[Template]

	Protocol Protocol
	Probe    string
	Service  string
	Soft     bool
	Regexp   string
	re       *pcre.Regexp
}

func MakeMatcher(probe ServiceProbe, match Match) (*Matcher, error) {
	var optsC, optsS int
	if strings.Contains(match.Flags, "i") {
		optsC |= pcre.CASELESS
	}
	optsC |= pcre.UTF8
	optsS |= pcre.STUDY_JIT_COMPILE

	re, err := pcre.CompileJIT(match.Regex, optsC, optsS)
	if err != nil {
		return nil, err
	}
	return &Matcher{
		Protocol: probe.Protocol,
		Probe:    probe.Name,
		Service:  match.Service,
		Info:     match.Info,
		Soft:     match.Soft,
		Regexp:   match.Regex,
		re:       &re,
	}, err
}

func (m *Matcher) MatchBytes(input []byte) MatchResult {

	matcher := m.re.NewMatcherString(intoUTF8(input), 0)
	err := error(nil)
	if matcher == nil {
		err = fmt.Errorf("can't create matcher")
	}
	return MatchResult{matcher, err}
}

func (m *Matcher) MatchRunes(input []rune) MatchResult {
	matcher := m.re.NewMatcherString(string(input), 0)
	err := error(nil)
	if matcher == nil {
		err = fmt.Errorf("can't create matcher")
	}
	return MatchResult{matcher, err}
}

func intoUTF8(input []byte) string {
	runes := make([]rune, 0, len(input))
	for len(input) > 0 {
		if r, size := utf8.DecodeRune(input); r != utf8.RuneError {
			runes = append(runes, r)
			input = input[size:]
		} else {
			runes = append(runes, rune(input[0]))
			input = input[1:]
		}
	}
	return string(runes)
}

func intoRunes2(input []byte) []rune {
	runes := make([]rune, 0, len(input))
	for len(input) > 0 {
		if r, size := utf8.DecodeRune(input); r != utf8.RuneError {
			runes = append(runes, r)
			input = input[size:]
		} else {
			runes = append(runes, rune(input[0]))
			input = input[1:]
		}
	}
	return runes
}

type MatchResult struct {
	match *pcre.Matcher
	err   error
}

func (r MatchResult) Found() bool { return r.match != nil && r.err == nil }
func (r MatchResult) Err() error  { return r.err }

func (r MatchResult) Render(tmpl Info[Template]) Info[string] {
	if r.Found() {
		var cpe []string
		for _, tmpl := range tmpl.CPE {
			cpe = append(cpe, tmpl.Render(r.match))
		}
		return Info[string]{
			VendorProductName: tmpl.VendorProductName.Render(r.match),
			Version:           tmpl.Version.Render(r.match),
			Info:              tmpl.Info.Render(r.match),
			Hostname:          tmpl.Hostname.Render(r.match),
			OS:                tmpl.OS.Render(r.match),
			DeviceType:        tmpl.DeviceType.Render(r.match),
			CPE:               cpe,
		}
	}
	return Info[string]{}
}
