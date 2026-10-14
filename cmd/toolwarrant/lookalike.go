package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// mixedWord is a word of the definition that mixes scripts, with the JSON
// path of the string it was found in.
type mixedWord struct {
	path string
	textdiff.MixedWord
}

// suspicion is what the approve review found: the characters a person cannot
// see or a terminal would obey, the words that mix scripts outside the UTS #39
// Highly Restrictive profile, and the values and keys that read the same as
// the approved version's but are spelt with other code points. The three
// classes share --accept-suspicious: each is text an approver cannot see for
// what it is.
type suspicion struct {
	chars []located
	mixed []mixedWord
	swaps []textdiff.LookAlikeChange
	// against is the approved version the swaps were found against; 0 while
	// nothing is approved, when there are no swaps to find.
	against int
}

func (s suspicion) total() int { return len(s.chars) + len(s.mixed) + len(s.swaps) }

// describe renders the non-zero counts: "3 suspicious character(s), 1
// mixed-script word(s) and 2 look-alike change(s)".
func (s suspicion) describe() string {
	var parts []string
	for _, p := range []struct {
		n    int
		noun string
	}{{len(s.chars), "suspicious character(s)"}, {len(s.mixed), "mixed-script word(s)"}, {len(s.swaps), "look-alike change(s)"}} {
		if p.n > 0 {
			parts = append(parts, strconv.Itoa(p.n)+" "+p.noun)
		}
	}
	if len(parts) <= 1 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// print lists every finding on stderr, one heading per class. Paths the CLI
// built from raw keys go through cell; the paths textdiff renders are escaped
// already, and so are the code-point details.
func (s suspicion) print(stderr *stream) {
	if len(s.chars) > 0 {
		stderr.printf("suspicious characters in this definition:\n")
		for _, f := range s.chars {
			stderr.printf("  %s byte %d: U+%04X %s (%s)\n", cell(f.path), f.Offset, f.Rune, f.Name, f.Category)
		}
	}
	if len(s.mixed) > 0 {
		stderr.printf("mixed-script words in this definition:\n")
		for _, w := range s.mixed {
			stderr.printf("  %s byte %d: %s\n", cell(w.path), w.Offset, w.Detail())
		}
	}
	if len(s.swaps) > 0 {
		stderr.printf("look-alike changes against the approved version %d:\n", s.against)
		for _, c := range s.swaps {
			stderr.printf("  %s: %s\n", c.Where(), c.Detail())
		}
	}
}

// approvedVersion returns the approved version when one exists and it is not
// the version being approved; otherwise there is nothing to compare with.
func approvedVersion(approved string, versions []catalog.VersionView, v catalog.VersionView) (*catalog.VersionView, error) {
	if approved == "" || approved == v.Digest {
		return nil, nil
	}
	base, err := versionByDigest(versions, approved)
	if err != nil {
		return nil, err
	}
	return &base, nil
}

// gatherSuspicion runs the three scans. The look-alike comparison needs an
// approved version; the catalog re-hashes every canonical form it hands out,
// so a document textdiff refuses is a fault to stop on, named by version
// number, never by its bytes.
func gatherSuspicion(approved *catalog.VersionView, v catalog.VersionView) (suspicion, error) {
	chars, err := scanStrings(v.Canonical)
	if err != nil {
		return suspicion{}, err
	}
	mixed, err := scanMixedScripts(v.Canonical)
	if err != nil {
		return suspicion{}, err
	}
	s := suspicion{chars: chars, mixed: mixed}
	if approved == nil {
		return s, nil
	}
	s.swaps, err = textdiff.LookAlikeChanges(approved.Canonical, v.Canonical)
	if err != nil {
		return suspicion{}, fmt.Errorf("compare version %d with the approved version %d: %w", v.No, approved.No, err)
	}
	s.against = approved.No
	return s, nil
}

// scanMixedScripts decodes the definition and runs textdiff.MixedScriptWords
// over every string value and object key, keys included because a parameter
// name is text the model reads too.
func scanMixedScripts(canonical []byte) ([]mixedWord, error) {
	doc, err := decodeDefinition(canonical)
	if err != nil {
		return nil, err
	}
	var out []mixedWord
	eachString(rootPath, doc, func(path, s string) {
		for _, w := range textdiff.MixedScriptWords(s) {
			out = append(out, mixedWord{path: path, MixedWord: w})
		}
	})
	return out, nil
}

// decodeDefinition parses the canonical definition with numbers kept as text.
func decodeDefinition(canonical []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode definition: %w", err)
	}
	return doc, nil
}

// eachString calls visit for every string value and object key of v in a
// fixed order (keys sorted, a key before its value, arrays by index). A key's
// path carries the " (key)" suffix.
func eachString(path string, v any, visit func(path, s string)) {
	switch x := v.(type) {
	case string:
		visit(path, x)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := path + "." + k
			visit(child+keySuffix, k)
			eachString(child, x[k], visit)
		}
	case []any:
		for i, e := range x {
			eachString(fmt.Sprintf("%s[%d]", path, i), e, visit)
		}
	}
}
