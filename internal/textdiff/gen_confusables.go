//go:build ignore

// gen_confusables.go writes confusables_table.go, the sorted table Skeleton
// looks code points up in, from the UTS #39 confusables file vendored under
// third_party/unicode. It is run by scripts/gen-confusables.sh (also as
// --check in the lint job) and by go generate in this package.
//
// Why a generator and a committed table: the build must not depend on the
// data file or on parsing it at start-up, and a committed generated file is
// only trustworthy when anyone can regenerate it byte for byte. The vendored
// file is data, read with the same care as upstream text: every line is
// bounded, every code point is checked, a duplicate source or a malformed
// field stops the run, and nothing from the file is echoed into an error.
//
// The header version is pinned: the file must say "Version: 18.0.0" (the
// confusablesVersion below), the version that was vendored and recorded in the
// README licence paragraph. Any other version is refused, so the table cannot
// move without the pin, the test
// TestConfusables_versionIsTheVendoredHeaderAndNotOlderThanTheToolchains and
// the licence record moving with it. The toolchain's unicode.Version (17.0.0
// for go1.27) is allowed to lag: see the comment on Skeleton.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// confusablesVersion is the UTS #39 version the vendored file must carry.
	confusablesVersion = "18.0.0"
	versionPrefix      = "# Version: "
	// fieldType is the only mapping type confusables.txt has carried since
	// Unicode 9; the generator refuses any other, since the skeleton
	// algorithm is defined over this one table.
	fieldType = "MA"
	// maxLineBytes bounds one line of the data file; the longest real line is
	// under 300 bytes.
	maxLineBytes = 4096
	// maxMappings bounds the table; the file has about 6,700 entries.
	maxMappings = 100000
	// maxTargetRunes bounds one mapping target; the longest real one is 18.
	maxTargetRunes = 64
	minFields      = 3
	surrogateStart = 0xD800
	surrogateEnd   = 0xDFFF
	hexBase        = 16
	runeBits       = 32
	bmpEnd         = 0xFFFF
)

// mapping is one line of the file: a source code point and its prototype.
type mapping struct {
	src rune
	dst []rune
}

func main() {
	in := flag.String("in", "../../third_party/unicode/confusables.txt", "the vendored UTS #39 confusables file")
	out := flag.String("out", "confusables_table.go", "the Go file to write")
	flag.Parse()
	if err := run(*in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "gen_confusables:", err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	f, err := os.Open(in)
	if err != nil {
		return fmt.Errorf("open data file: %w", err)
	}
	defer func() { _ = f.Close() }()
	version, mappings, err := parse(f)
	if err != nil {
		return fmt.Errorf("parse %s: %w", in, err)
	}
	if version != confusablesVersion {
		return fmt.Errorf("the data file header says version %q, the generator pins %s; vendor the pinned version or move the pin, the licence record and the test together", version, confusablesVersion)
	}
	src, err := render(version, mappings)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, src, 0o644); err != nil {
		return fmt.Errorf("write table: %w", err)
	}
	return nil
}

// parse reads the header version and every mapping line. The mappings are
// returned sorted by source, so the table supports a binary search.
func parse(f *os.File) (string, []mapping, error) {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
	version := ""
	seen := map[rune]bool{}
	var mappings []mapping
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if strings.HasPrefix(text, versionPrefix) {
			version = strings.TrimSpace(strings.TrimPrefix(text, versionPrefix))
			continue
		}
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		m, err := parseLine(text)
		if err != nil {
			return "", nil, fmt.Errorf("line %d: %w", line, err)
		}
		if seen[m.src] {
			return "", nil, fmt.Errorf("line %d: duplicate source code point", line)
		}
		seen[m.src] = true
		mappings = append(mappings, m)
		if len(mappings) > maxMappings {
			return "", nil, fmt.Errorf("more than %d mappings", maxMappings)
		}
	}
	if err := sc.Err(); err != nil {
		return "", nil, fmt.Errorf("read: %w", err)
	}
	if version == "" {
		return "", nil, errors.New("no \"# Version:\" header")
	}
	if len(mappings) == 0 {
		return "", nil, errors.New("no mappings")
	}
	sort.Slice(mappings, func(i, j int) bool { return mappings[i].src < mappings[j].src })
	return version, mappings, nil
}

// parseLine reads "SRC ; DST... ; MA # comment". The comment is ignored.
func parseLine(text string) (mapping, error) {
	body, _, _ := strings.Cut(text, "#")
	fields := strings.Split(body, ";")
	if len(fields) < minFields {
		return mapping{}, errors.New("fewer than three fields")
	}
	if typ := strings.TrimSpace(fields[2]); typ != fieldType {
		return mapping{}, fmt.Errorf("mapping type is not %s", fieldType)
	}
	src, err := parseRunes(fields[0])
	if err != nil {
		return mapping{}, fmt.Errorf("source: %w", err)
	}
	if len(src) != 1 {
		return mapping{}, errors.New("source is not exactly one code point")
	}
	dst, err := parseRunes(fields[1])
	if err != nil {
		return mapping{}, fmt.Errorf("target: %w", err)
	}
	return mapping{src: src[0], dst: dst}, nil
}

// parseRunes reads space-separated hex code points, each a valid scalar value.
func parseRunes(field string) ([]rune, error) {
	words := strings.Fields(field)
	if len(words) == 0 || len(words) > maxTargetRunes {
		return nil, fmt.Errorf("%d code points", len(words))
	}
	out := make([]rune, 0, len(words))
	for _, w := range words {
		v, err := strconv.ParseUint(w, hexBase, runeBits)
		if err != nil {
			return nil, errors.New("not a hex code point")
		}
		r := rune(v)
		if !utf8.ValidRune(r) || (r >= surrogateStart && r <= surrogateEnd) {
			return nil, errors.New("not a Unicode scalar value")
		}
		out = append(out, r)
	}
	return out, nil
}

// render writes the Go source and formats it, so the committed file is
// gofmt-clean whatever this generator's own spacing.
func render(version string, mappings []mapping) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by gen_confusables.go from third_party/unicode/confusables.txt (UTS #39 confusables, Version: %s, %d mappings); DO NOT EDIT.\n\n", version, len(mappings))
	b.WriteString("package textdiff\n\n")
	fmt.Fprintf(&b, "// confusablesVersion is the UTS #39 version of the vendored data file the\n// table below was generated from.\nconst confusablesVersion = %q\n\n", version)
	b.WriteString("// confusable maps one source code point to its prototype, the code points\n// that look the same. Every non-ASCII target is written as an escape so that\n// no look-alike character stands raw in this file.\ntype confusable struct {\n\tsrc rune\n\tdst string\n}\n\n")
	b.WriteString("// confusables is the whole table sorted by source code point, which is what\n// confusableOf's binary search needs. It is generated data: built once by the\n// compiler and never written.\nvar confusables = [...]confusable{\n")
	for _, m := range mappings {
		fmt.Fprintf(&b, "\t{0x%04X, %s},\n", m.src, goString(m.dst))
	}
	b.WriteString("}\n")
	src, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated source: %w", err)
	}
	return src, nil
}

// goString renders runes as a Go string literal of escapes. ASCII stays as
// itself when it needs no escaping; everything else is \u or \U.
func goString(rs []rune) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range rs {
		switch {
		case r >= ' ' && r <= '~' && r != '"' && r != '\\':
			sb.WriteRune(r)
		case r <= bmpEnd:
			fmt.Fprintf(&sb, "\\u%04X", r)
		default:
			fmt.Fprintf(&sb, "\\U%08X", r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}
