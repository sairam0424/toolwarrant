package trust

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// The operator-name rule, D7. It is the rule of internal/catalog/validate.go
// normalizeActor, re-implemented here from the same pattern so this package
// imports neither catalog nor cmd; TestNormalizeName_AgreesWithCatalogsNormalizeActorTable
// pins the two on the catalog's own table. internal/signing's isActorName is
// the shape half of the same rule, applied to names a payload already carries.
const (
	// maxNameBytes bounds a name before normalisation; the normalised form is
	// bounded by the pattern (catalog's maxActorNameBytes).
	maxNameBytes = 256
	// maxNameLen is the length the pattern allows: one leading character and
	// up to 63 more (catalog's maxActorNameLen).
	maxNameLen = 64
	// namePattern is the rule as every error states it.
	namePattern = "^[a-z0-9][a-z0-9._@-]{0,63}$"
	// namePunctuation is what the pattern allows after the first character
	// besides letters and digits.
	namePunctuation = "._@-"
)

// ErrName is returned for an operator name the D7 rule refuses.
var ErrName = errors.New("trust: operator name is not a D7 name")

// NormalizeName returns the canonical form of an operator name: NFKC, then
// lower-cased, then checked against namePattern, so that "Alice", "alice" and
// a full-width or ligature spelling are one identity and nothing that renders
// like another name is accepted. A name already in canonical form is returned
// unchanged, which is what lets a stored actor be compared with a listed one.
func NormalizeName(name string) (string, error) {
	switch {
	case name == "":
		return "", fmt.Errorf("%w: empty", ErrName)
	case len(name) > maxNameBytes:
		return "", fmt.Errorf("%w: longer than %d bytes", ErrName, maxNameBytes)
	case !utf8.ValidString(name):
		return "", fmt.Errorf("%w: not valid UTF-8", ErrName)
	}
	n := strings.ToLower(norm.NFKC.String(name))
	if !isName(n) {
		return "", fmt.Errorf("%w: %s must match %s after NFKC normalisation and lower-casing", ErrName, strconv.Quote(name), namePattern)
	}
	return n, nil
}

// isName matches namePattern by hand, as the catalog does, so the pattern
// string in the error is the rule and no regexp state is kept.
func isName(name string) bool {
	if name == "" || len(name) > maxNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isLowerAlnum(c) || (i > 0 && strings.IndexByte(namePunctuation, c) >= 0) {
			continue
		}
		return false
	}
	return true
}

// isLowerAlnum reports whether c is a lower-case ASCII letter or a digit.
func isLowerAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
