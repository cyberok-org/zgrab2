package template

import (
	"strconv"
	"testing"

	"github.com/GRbit/go-pcre"
	"github.com/stretchr/testify/require"
)

var itoa = strconv.Itoa

func TestBuiltinFuncs(t *testing.T) {
	test := func(regex, input, template, output string) {
		t.Helper()
		re, err := pcre.CompileJIT(regex, 0, 0)
		m := re.NewMatcherString(input, 0)
		require.NoError(t, err)
		require.True(t, m != nil, "no match found")
		require.Equal(t, output, Parse([]byte(template)).Render(m))
	}
	test("(.+)", "AAABBC", `$SUBST(1,"A","a")`, "aaaBBC")
	test("(.+)", "A\x00B\x10C", `$P(1)`, "ABC")
	test("(.+)", "\x11\x22\x33", `$I(1):$I(1,">"):$I(1,"<")`, "0:"+itoa(0x112233)+":"+itoa(0x332211))
}
