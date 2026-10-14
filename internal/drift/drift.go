// Package drift classifies what changed between two versions of a tool
// definition, so that an approver reads a grade and the kinds of change before
// the escaped diff. The classification is advisory: the gate stays the digest
// (D1), and nothing here approves, hides or serves anything. Both documents are
// hostile text: every path in a finding goes through textdiff.Escape and no
// detail ever carries upstream bytes, so a finding can be printed as it is.
// textdiff renders and drift judges; drift imports textdiff, never the reverse.
package drift

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

// Severity grades a finding. None is the grade of a report without findings;
// the other three order as Info < Warning < Critical, so the largest one in a
// report is the grade an approver reads first.
type Severity int

const (
	// None is the grade of a report without findings.
	None Severity = iota
	// Info marks a change a host only displays: the title or the icons.
	Info
	// Warning marks a change that alters what the model reads or what the
	// host does with the tool without widening what the tool may do.
	Warning
	// Critical marks a change that widens what the tool may do or breaks
	// the contract the approver reviewed: a parameter removed, retyped or
	// newly required, an annotation hint loosened, the name changed.
	Critical
)

// String renders the grade in upper case, as the commands print it.
func (s Severity) String() string {
	switch s {
	case None:
		return "none"
	case Info:
		return "INFO"
	case Warning:
		return "WARNING"
	case Critical:
		return "CRITICAL"
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// Kind names one kind of change. The kinds are the taxonomy decision D21 (b)
// records; a tool that appears or disappears is a crawl-level change
// (catalog ChangeNew, ChangeMissing, ChangeDeprecated), not a kind here.
type Kind string

const (
	// ParameterRemoved is a member of inputSchema.properties that is gone.
	ParameterRemoved Kind = "parameter-removed"
	// ParameterTypeChanged is a parameter whose JSON Schema type differs.
	ParameterTypeChanged Kind = "parameter-type-changed"
	// RequiredParameterAdded is a new parameter that inputSchema.required lists.
	RequiredParameterAdded Kind = "required-parameter-added"
	// ParameterMadeRequired is an existing parameter newly listed in required.
	ParameterMadeRequired Kind = "parameter-made-required"
	// AnnotationsLoosened is a hint moved away from its safe value:
	// readOnlyHint true to false, destructiveHint false to true,
	// openWorldHint false to true, idempotentHint true to false.
	AnnotationsLoosened Kind = "annotations-loosened"
	// NameChanged is a different name under the same canonical document.
	NameChanged Kind = "name-changed"
	// DescriptionChanged is graded WARNING, not INFO (owner decision O-6):
	// the description-first rug pull is threat-model row 3.
	DescriptionChanged Kind = "description-changed"
	// OptionalParameterAdded is a new parameter that required does not list.
	OptionalParameterAdded Kind = "optional-parameter-added"
	// InputSchemaChanged is any other inputSchema change: an enum, a
	// constraint, a nested schema, a parameter made optional.
	InputSchemaChanged Kind = "input-schema-changed"
	// OutputSchemaChanged is any outputSchema change.
	OutputSchemaChanged Kind = "output-schema-changed"
	// AnnotationsChanged is any other annotations change, a hint tightened
	// included.
	AnnotationsChanged Kind = "annotations-changed"
	// MetaChanged is any _meta change: hosts act on _meta (D1) and
	// agentgateway acts on _meta.ui.
	MetaChanged Kind = "meta-changed"
	// Other is a top-level key this package does not know.
	Other Kind = "other"
	// TitleChanged is a different display title.
	TitleChanged Kind = "title-changed"
	// IconsChanged is a different icons list.
	IconsChanged Kind = "icons-changed"
)

// Severity returns the grade of a kind. A kind this package does not know is
// graded Critical, failing closed.
func (k Kind) Severity() Severity {
	switch k {
	case DescriptionChanged, OptionalParameterAdded, InputSchemaChanged, OutputSchemaChanged,
		AnnotationsChanged, MetaChanged, Other:
		return Warning
	case TitleChanged, IconsChanged:
		return Info
	}
	return Critical
}

// Finding is one classified change. Path is the JSON path of the member, in
// the $.a["b c"] form textdiff prints, escaped; Detail is a fixed word such as
// "added", "removed", "changed", "made required", or a transition such as
// "string -> integer" and "true -> false" built from a closed vocabulary.
// Neither carries bytes of the definitions.
type Finding struct {
	Kind     Kind
	Severity Severity
	Path     string
	Detail   string
}

// Report is the classification of one change: its findings sorted by severity,
// the most severe first, then by path.
type Report struct {
	Findings []Finding
}

// Max returns the largest severity among the findings, None when there are
// none.
func (r Report) Max() Severity {
	m := None
	for _, f := range r.Findings {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// Kinds lists every kind once, the most severe first and kinds of one grade by
// name.
func (r Report) Kinds() []Kind {
	seen := make(map[Kind]bool, len(r.Findings))
	out := make([]Kind, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !seen[f.Kind] {
			seen[f.Kind] = true
			out = append(out, f.Kind)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if si, sj := out[i].Severity(), out[j].Severity(); si != sj {
			return si > sj
		}
		return out[i] < out[j]
	})
	return out
}

// Summary renders the grade and the kinds on one line, for example
// `CRITICAL (parameter-removed, description-changed)`, or `none` for a report
// without findings.
func (r Report) Summary() string {
	if len(r.Findings) == 0 {
		return None.String()
	}
	kinds := r.Kinds()
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = string(k)
	}
	return r.Max().String() + " (" + strings.Join(names, ", ") + ")"
}

// The reasons Compare refuses a document. None of them repeats a byte of it.
var (
	// ErrNotUTF8 is a document that is not valid UTF-8.
	ErrNotUTF8 = errors.New("not valid UTF-8")
	// ErrNotJSON is a document that is not one well-formed JSON value.
	ErrNotJSON = errors.New("not a well-formed JSON value")
	// ErrTrailingData is a document with bytes after its one value.
	ErrTrailingData = errors.New("unexpected data after the document")
	// ErrNotObject is a document whose value is not a JSON object.
	ErrNotObject = errors.New("not a JSON object")
)

// Compare classifies the change from one tool definition to another. Both are
// canonical documents as catalog.VersionView.Canonical hands them out; any
// valid JSON object is accepted. It refuses, without echoing a byte of either
// document, anything that is not exactly one JSON object in valid UTF-8.
func Compare(fromCanonical, toCanonical []byte) (Report, error) {
	from, err := decodeObject(fromCanonical)
	if err != nil {
		return Report{}, fmt.Errorf("drift: from document: %w", err)
	}
	to, err := decodeObject(toCanonical)
	if err != nil {
		return Report{}, fmt.Errorf("drift: to document: %w", err)
	}
	c := &classifier{}
	c.compareTop(from, to)
	c.sort()
	return Report{Findings: c.out}, nil
}

// decodeObject parses exactly one JSON object, numbers kept as their text, and
// refuses invalid UTF-8 and trailing data as textdiff does, since a decoder
// would otherwise turn bad bytes into U+FFFD and classify a text the upstream
// never sent.
func decodeObject(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, ErrNotUTF8
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, ErrNotJSON
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrTrailingData
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, ErrNotObject
	}
	return obj, nil
}

// The top-level members of a tool definition with a rule of their own.
const (
	keyName         = "name"
	keyDescription  = "description"
	keyTitle        = "title"
	keyIcons        = "icons"
	keyAnnotations  = "annotations"
	keyInputSchema  = "inputSchema"
	keyOutputSchema = "outputSchema"
	keyMeta         = "_meta"
	rootPath        = "$"
)

// value is one side of a comparison: the decoded JSON value and whether the
// member was present at all, since a present null and an absent member differ.
type value struct {
	v       any
	present bool
}

// object returns the value as a JSON object, or false when it is absent or
// anything else.
func (v value) object() (map[string]any, bool) {
	m, ok := v.v.(map[string]any)
	return m, ok && v.present
}

// memberOf reads one member of an object (a nil object has none).
func memberOf(obj map[string]any, key string) value {
	v, ok := obj[key]
	return value{v: v, present: ok}
}

// differ reports whether the two sides are not the same member: one absent,
// or both present with different values.
func differ(f, t value) bool {
	if f.present != t.present {
		return true
	}
	return f.present && !reflect.DeepEqual(f.v, t.v)
}

// presence is the detail word for a member that differs.
func presence(f, t value) string {
	switch {
	case !t.present:
		return "removed"
	case !f.present:
		return "added"
	}
	return "changed"
}

// classifier accumulates findings while the two documents are walked.
type classifier struct{ out []Finding }

func (c *classifier) add(kind Kind, path, detail string) {
	c.out = append(c.out, Finding{Kind: kind, Severity: kind.Severity(), Path: path, Detail: detail})
}

// compareTop applies the rule of each top-level member that differs.
func (c *classifier) compareTop(from, to map[string]any) {
	for _, k := range mergedKeys(from, to) {
		f, t := memberOf(from, k), memberOf(to, k)
		if !differ(f, t) {
			continue
		}
		path := rootPath + segment(k)
		switch k {
		case keyName:
			c.add(NameChanged, path, presence(f, t))
		case keyDescription:
			c.add(DescriptionChanged, path, presence(f, t))
		case keyTitle:
			c.add(TitleChanged, path, presence(f, t))
		case keyIcons:
			c.add(IconsChanged, path, presence(f, t))
		case keyAnnotations:
			c.compareAnnotations(path, f, t)
		case keyInputSchema:
			c.compareInputSchema(path, f, t)
		case keyOutputSchema:
			c.add(OutputSchemaChanged, path, presence(f, t))
		case keyMeta:
			c.compareMembers(MetaChanged, path, f, t)
		default:
			c.add(Other, path, presence(f, t))
		}
	}
}

// compareMembers reports one finding of kind per differing member when both
// sides are objects, and one for the member itself otherwise.
func (c *classifier) compareMembers(kind Kind, path string, f, t value) {
	fo, fok := f.object()
	to, tok := t.object()
	if !fok || !tok {
		c.add(kind, path, presence(f, t))
		return
	}
	for _, k := range mergedKeys(fo, to) {
		fm, tm := memberOf(fo, k), memberOf(to, k)
		if differ(fm, tm) {
			c.add(kind, path+segment(k), presence(fm, tm))
		}
	}
}

// sort orders the findings by severity, the most severe first, then by path,
// kind and detail, so two runs over the same documents print the same list.
func (c *classifier) sort() {
	sort.Slice(c.out, func(i, j int) bool {
		a, b := c.out[i], c.out[j]
		switch {
		case a.Severity != b.Severity:
			return a.Severity > b.Severity
		case a.Path != b.Path:
			return a.Path < b.Path
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
}
