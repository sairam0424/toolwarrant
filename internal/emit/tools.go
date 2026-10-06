package emit

import (
	"slices"
	"strings"
)

// Reasons reported in Skipped. They are constants so callers and tests can
// match on them without parsing prose.
const (
	// ReasonEmptyName marks an approved tool whose name is empty.
	ReasonEmptyName = "tool name is empty"
	// ReasonNameTooLong marks a name longer than MaxToolNameLen bytes.
	ReasonNameTooLong = "tool name is too long"
	// ReasonNotPrintableASCII marks a name with a control or non-ASCII
	// character.
	ReasonNotPrintableASCII = "tool name has characters outside printable ASCII"
)

// MaxToolNameLen bounds a tool name the emitter will put in an allow rule.
// MCP recommends 1-128 characters; a longer name is almost certainly abuse,
// and leaving it hidden is the safe direction.
const MaxToolNameLen = 128

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

// unsafeReason returns why name must not be emitted, or "" if it is safe.
func unsafeReason(name string) string {
	switch {
	case name == "":
		return ReasonEmptyName
	case len(name) > MaxToolNameLen:
		return ReasonNameTooLong
	case !isPrintableASCII(name):
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
