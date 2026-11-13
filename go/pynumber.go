package fasten

import (
	"strconv"
	"strings"
)

// pyNumbers rewrites every number token in the JSON b the way CPython's
// json.dumps renders the value json.loads gives for it (spec §1.3), so a
// detail Go seals hashes the same bytes Python gets from the stored token:
//   - a token with no '.', 'e' or 'E' is an int to Python and is kept as
//     written, except "-0", which Python reads as 0;
//   - any other token is a float to Python and is written as repr() writes
//     it (see pyFloatRepr).
//
// Tokens that already have CPython's form, as every Python-sealed row does,
// come out unchanged.
func pyNumbers(b []byte) []byte {
	var out []byte // nil until the first changed token
	inString, escaped := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			if out != nil {
				out = append(out, c)
			}
			continue
		}
		if c == '"' {
			inString = true
		} else if c == '-' || (c >= '0' && c <= '9') {
			j := i + 1
			for j < len(b) && strings.IndexByte("0123456789+-.eE", b[j]) >= 0 {
				j++
			}
			tok := string(b[i:j])
			if py := pyNumberToken(tok); py != tok {
				if out == nil {
					out = append(make([]byte, 0, len(b)+8), b[:i]...)
				}
				out = append(out, py...)
				i = j - 1
				continue
			}
			if out != nil {
				out = append(out, b[i:j]...)
			}
			i = j - 1
			continue
		}
		if out != nil {
			out = append(out, c)
		}
	}
	if out == nil {
		return b
	}
	return out
}

func pyNumberToken(tok string) string {
	if !strings.ContainsAny(tok, ".eE") {
		if tok == "-0" {
			return "0"
		}
		return tok
	}
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		return tok
	}
	return pyFloatRepr(f)
}

// pyFloatRepr returns CPython's repr(f) for a finite float: the shortest
// digits that round-trip, in fixed notation when the decimal exponent is
// from -4 to 15 (with ".0" on whole numbers), otherwise in scientific
// notation with a signed exponent of at least two digits: 5e-05, 1e+16.
func pyFloatRepr(f float64) string {
	s := strconv.FormatFloat(f, 'e', -1, 64) // "-1.25e-05"
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	mant, expStr, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	var out string
	if decpt := exp + 1; decpt > -4 && decpt <= 16 {
		switch {
		case decpt <= 0:
			out = "0." + strings.Repeat("0", -decpt) + digits
		case decpt >= len(digits):
			out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
		default:
			out = digits[:decpt] + "." + digits[decpt:]
		}
	} else {
		out = digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign, exp = "-", -exp
		}
		e := strconv.Itoa(exp)
		if len(e) < 2 {
			e = "0" + e
		}
		out += "e" + sign + e
	}
	if neg {
		return "-" + out
	}
	return out
}
