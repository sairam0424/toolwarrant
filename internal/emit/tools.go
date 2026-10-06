package emit

import (
	"slices"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/toolname"
)

// Reasons reported in Skipped. They are constants so callers and tests can
// match on them without parsing prose. ReasonInvalidName is a prefix: it is
// followed by ": " and the shared rule's own explanation, which never echoes
// the name.
const (
	// ReasonEmptyName marks an approved tool whose name is empty.
	ReasonEmptyName = "tool name is empty"
	// ReasonNameTooLong marks a name longer than MaxToolNameLen bytes.
	ReasonNameTooLong = "tool name is too long"
	// ReasonInvalidName marks a name the shared tool-name rule
	// (internal/toolname) refuses: invalid UTF-8, a spelling that is not NFC,
	// a control or invisible character, or stray spaces. The crawler and the
	// catalog apply the same rule, so such a name should never reach the
	// emitter; if one does, hiding it is the safe direction.
	ReasonInvalidName = "tool name fails the shared tool-name rule"
	// ReasonNotPrintableASCII marks a name the shared rule accepts but that
	// cannot be written into a CEL rule as plain printable ASCII. The emitter
	// could escape it, but a rule an operator cannot read byte for byte is not
	// reviewable, so the tool stays hidden and is reported instead.
	ReasonNotPrintableASCII = "tool name has characters outside printable ASCII"
)

// MaxToolNameLen bounds a tool name the emitter will put in an allow rule. It
// is the shared rule's cap, so a name the catalog accepted is never too long
// here: the review found three different caps across the crawler, the catalog
// and the emitter, which let an approved tool silently never be served.
const MaxToolNameLen = toolname.MaxBytes

const (
	// celNeverMatches is the allow expression used when nothing can be
	// allowed. agentgateway treats an empty or deny-only rule set as "allow
	// everything", so an explicit allow rule that is always false is what
	// keeps a server with no approved tools fully hidden.
	celNeverMatches = "false"
	celToolName     = "mcp.tool.name"
	celEquals       = " == "
	celOr           = " || "
)

// toolPlan is the outcome of classifying one server's approved tools.
type toolPlan struct {
	allowed []string
	skipped []Skipped
}

// classifyTools sorts and de-duplicates the approved tool names of one server
// and splits them into names that can be written into the allow rule and names
// that cannot. The input slice is not modified.
func classifyTools(server string, names []string) toolPlan {
	unique := slices.Clone(names)
	slices.Sort(unique)
	unique = slices.Compact(unique)

	var plan toolPlan
	for _, name := range unique {
		if reason := unsafeReason(name); reason != "" {
			plan.skipped = append(plan.skipped, Skipped{Server: server, Tool: name, Reason: reason})
			continue
		}
		plan.allowed = append(plan.allowed, name)
	}
	return plan
}

// unsafeReason returns why name must not be emitted, or "" if it is safe. The
// shared rule runs first so its reasons are reported as such; the printable
// ASCII rule is the emitter's own extra requirement on top.
func unsafeReason(name string) string {
	switch {
	case name == "":
		return ReasonEmptyName
	case len(name) > MaxToolNameLen:
		return ReasonNameTooLong
	}
	if err := toolname.Validate(name); err != nil {
		detail := strings.TrimPrefix(err.Error(), toolname.ErrInvalid.Error()+": ")
		return ReasonInvalidName + ": " + detail
	}
	if !isPrintableASCII(name) {
		return ReasonNotPrintableASCII
	}
	return ""
}

// allowExpression builds the CEL allow rule for the given safe, sorted tool
// names: a disjunction of exact name comparisons, or the never-matching
// literal when there are none. The result is never empty.
func allowExpression(names []string) string {
	if len(names) == 0 {
		return celNeverMatches
	}
	terms := make([]string, len(names))
	for i, name := range names {
		terms[i] = celToolName + celEquals + quote(name)
	}
	return strings.Join(terms, celOr)
}
