package nmap

import (
	"fmt"
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

type RegexStat struct {
	Regex    string        `json:"regex"`
	Duration time.Duration `json:"time"`
	Service  string        `json:"service"`
	Error    error         `json:"error"`
}

type ExtractResult struct {
	Probe     string `json:"probe"`
	Service   string `json:"service"`
	Regex     string `json:"regex"`
	SoftMatch bool   `json:"softmatch"`
	Info[string]
}

func (ms Matchers) ExtractInfoFromBytes(input []byte) []ExtractResult {
	return ms.ExtractInfoFromRunes(intoRunes(input))
}

func (ms Matchers) ExtractInfoFromRunes(input []rune) []ExtractResult {
	var result []ExtractResult
	var stats []RegexStat

	var matchersTotal int
	var matchersPassed int
	var matchersError int
	t1 := time.Now().UTC()

	for _, m := range ms {
		ts := time.Now().UTC()
		r := m.MatchRunes(input)
		dr := time.Now().UTC().Sub(ts)

		if dr > time.Duration(time.Millisecond*200) {
			stats = append(stats, RegexStat{
				Regex:    m.re.String(),
				Service:  m.App,
				Error:    r.Err(),
				Duration: time.Duration(dr.Milliseconds()),
			})
		}

		matchersTotal++
		if err := r.Err(); err != nil {
			fmt.Println("ERROR: ", err)
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

	if len(stats) > 0 {

		lf := log.WithFields(log.Fields{
			"banner":   string(input),
			"tolal":    matchersTotal,
			"matched":  matchersPassed,
			"errors":   matchersError,
			"duration": time.Duration(time.Now().UTC().Sub(t1).Milliseconds()),
			"length":   len(input),
			"slow":     stats,
		})
		lf.Info("-")
	}

	// log.Infof("STAT total: %d, PASSED:  %d, ERROR: %d, time: %s, input size: %d",
	// 	matchersTotal, matchersPassed, matchersError, time.Now().UTC().Sub(t1), len(input))

	return result

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
