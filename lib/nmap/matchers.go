package nmap

import (
	"io"
	"os"
	"time"

	"github.com/gobwas/glob"

	log "github.com/sirupsen/logrus"
)

type Matchers []*Matcher

func (ms *Matchers) Load(in io.Reader) error {
	probes, err := ParseServiceProbes(in)
	if err != nil {
		return err
	}

	var matchers Matchers
	for _, probe := range probes {
		for _, match := range probe.Matches {
			m, err := MakeMatcher(probe, match)
			if err != nil {
				return err
			}
			matchers = append(matchers, m)
		}
	}

	log.Infof("Loaded %d matchers", len(matchers))
	*ms = matchers
	return nil
}

func (ms Matchers) Filter(fn func(*Matcher) bool) Matchers {
	var filtered []*Matcher
	for _, m := range ms {
		if fn(m) {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

// Filter matchers using GLOB-pattern.
// Matchers are identified with `<probe>/<service>` name.
func (ms Matchers) FilterGlob(pattern string) Matchers {
	compiled, err := glob.Compile("{" + pattern + "}")
	if err != nil {
		return nil
	}
	return ms.Filter(func(m *Matcher) bool {
		name := m.Probe + "/" + m.Service
		return compiled.Match(name)
	})
}

type ExtractResult struct {
	Probe     string `json:"probe"`
	Service   string `json:"service"`
	Regex     string `json:"regex"`
	SoftMatch bool   `json:"softmatch"`
	Info[string]
}

func (ms Matchers) ExtractInfoFromBytes(input []byte) ([]ExtractResult, int, int, int, error) {
	// var result []ExtractResult
	// var errs []error
	// var matchersTotal int
	// var matchersPassed int
	// var matchersError int
	// return result, matchersTotal, matchersPassed, matchersError, errors.Join(errs...)
	return ms.ExtractInfoFromRunes(intoRunes(input))
}

func (ms Matchers) ExtractInfoFromRunes(input []rune) ([]ExtractResult, int, int, int, error) {
	var result []ExtractResult
	//var errs []error
	var matchersTotal int
	var matchersPassed int
	var matchersError int
	t1 := time.Now().UTC()
	for _, m := range ms {

		r := m.MatchRunes(input)
		matchersTotal++
		if err := r.Err(); err != nil {
			//errs = append(errs, err)
			matchersError++
			continue
		}
		if r.Found() {
			result = append(result, ExtractResult{
				Probe:     m.Probe,
				Service:   m.Service,
				Regex:     m.re.String(),
				SoftMatch: m.Soft,
				Info:      r.Render(m.Info),
			})
			matchersPassed++
		}
	}
	log.Infof("STAT total: %d, PASSED:  %d, ERROR: %d, time: %s, input size: %d",
		matchersTotal, matchersPassed, matchersError, time.Now().UTC().Sub(t1), len(input))
	return result, matchersTotal, matchersPassed, matchersError, nil //errors.Join(errs...)
}

var globalMatchers Matchers

func LoadServiceProbes(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return globalMatchers.Load(f)
}

func SelectMatchers(filter func(*Matcher) bool) Matchers {
	return globalMatchers.Filter(filter)
}

func SelectMatchersGlob(pattern string) Matchers {
	return globalMatchers.FilterGlob(pattern)
}
