package emit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// allowLinePrefix and routeLinePrefix are the indented line starts of the
// gateways form: routes are a top-level list, so a route starts at column 0
// and its allow rule six spaces in. The backend target's "- name:" line is
// indented, so routeLinePrefix cannot match it.
const (
	allowLinePrefix = "      - allow: "
	routeLinePrefix = "- name: "
	maxGenServers   = 5
	maxGenTools     = 12
)

// nastyNames are tool names chosen to break naive quoting.
var nastyNames = []string{
	`"`, `\`, `\"`, `"\`, `\\`, `A`, `\x41`, `' || true || '`, `") || true || ("`,
	"line\nbreak", "cr\r", "tab\t", "nul\x00", "\u202e", "é", "\U0001F600", "#", ": ", "- ", "{", "[", "&a", "*a", "!x", "%", "@", "`",
	" lead", "trail ", "two  spaces", "u\u0308ber", "zero\u200bwidth", strings.Repeat("l", 256), strings.Repeat("l", 257),
}

// oracleAllowed is an independent statement of which names may be emitted:
// 1-256 bytes of printable ASCII, no leading, trailing or doubled space.
func oracleAllowed(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return false
		}
	}
	return name[0] != ' ' && name[len(name)-1] != ' ' && !strings.Contains(name, "  ")
}

func drawServers(t *rapid.T) []Server {
	count := rapid.IntRange(1, maxGenServers).Draw(t, "servers")
	seen := map[string]bool{}
	var servers []Server
	for i := 0; i < count; i++ {
		name := rapid.StringMatching(`[a-z0-9][a-z0-9_-]{0,20}`).Draw(t, "name")
		if seen[name] {
			continue
		}
		seen[name] = true
		tools := rapid.SliceOfN(rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`[ -~]{0,20}`),
			rapid.SampledFrom(nastyNames),
			rapid.StringOf(rapid.SampledFrom([]rune(`"\ab|=. é`))),
		), 0, maxGenTools).Draw(t, "tools")
		secret := rapid.OneOf(rapid.Just(""), rapid.StringMatching(`[ -~]{16,40}`)).Draw(t, "secret")
		servers = append(servers, Server{
			Name: name, URL: testUpstreamURL, ProcessorAddr: fmt.Sprintf("127.0.0.1:%d", 9000+i), Secret: secret, ApprovedTools: tools,
		})
	}
	return servers
}

// TestPropertyEveryRouteHasAnAllowRule checks, for arbitrary tool names and
// secrets, that each route carries exactly one allow rule, that the rule
// decodes to exactly the safe approved tools, that the secret decodes to
// itself, that unsafe tools are reported, and that tool names never change
// the shape of the file.
func TestPropertyEveryRouteHasAnAllowRule(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		servers := drawServers(t)
		out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: servers})
		if err != nil {
			t.Fatalf("valid input rejected: %v", err)
		}
		routes := splitRoutes(string(out.YAML))
		if len(routes) != len(servers) {
			t.Fatalf("want %d routes, got %d", len(servers), len(routes))
		}
		sorted := slices.Clone(servers)
		slices.SortFunc(sorted, func(a, b Server) int { return strings.Compare(a.Name, b.Name) })

		var wantSkipped []Skipped
		for i, s := range sorted {
			allowed, skipped := oracleSplit(s)
			wantSkipped = append(wantSkipped, skipped...)
			got := decodeAllow(t, routes[i])
			if !slices.Equal(got, allowed) {
				t.Fatalf("server %q: allow rule decodes to %q, want %q", s.Name, got, allowed)
			}
			if secret := decodeSecret(t, routes[i]); secret != s.Secret {
				t.Fatalf("server %q: secret decodes to %q, want %q", s.Name, secret, s.Secret)
			}
		}
		if len(out.Skipped) != len(wantSkipped) {
			t.Fatalf("skipped %d tools, want %d", len(out.Skipped), len(wantSkipped))
		}
		for i := range wantSkipped {
			if out.Skipped[i].Server != wantSkipped[i].Server || out.Skipped[i].Tool != wantSkipped[i].Tool || out.Skipped[i].Reason == "" {
				t.Fatalf("skipped[%d] = %#v, want %#v", i, out.Skipped[i], wantSkipped[i])
			}
		}
		if _, ok := Verify(out.YAML); !ok {
			t.Fatalf("fresh output does not verify")
		}
		assertShapeIndependentOfTools(t, servers, out.YAML)
	})
}

// assertShapeIndependentOfTools re-renders the same servers with no tools and
// requires that only the allow lines and the hash line differ: tool names are
// data, never structure.
func assertShapeIndependentOfTools(t *rapid.T, servers []Server, got []byte) {
	bare := make([]Server, len(servers))
	for i, s := range servers {
		s.ApprovedTools = nil
		bare[i] = s
	}
	base, err := AgentGateway(Input{ListenPort: testListenPort, Servers: bare})
	if err != nil {
		t.Fatalf("bare render: %v", err)
	}
	gotLines := strings.Split(string(got), "\n")
	baseLines := strings.Split(string(base.YAML), "\n")
	if len(gotLines) != len(baseLines) {
		t.Fatalf("tool names changed the line count: %d vs %d", len(gotLines), len(baseLines))
	}
	for i := range gotLines {
		if gotLines[i] != baseLines[i] && !strings.HasPrefix(gotLines[i], allowLinePrefix) && !strings.HasPrefix(gotLines[i], hashLinePrefix) {
			t.Fatalf("line %d differs outside the allow rule: %q vs %q", i, gotLines[i], baseLines[i])
		}
	}
	for _, b := range got {
		if (b < 0x20 || b > 0x7e) && b != '\n' {
			t.Fatalf("output contains byte %#x", b)
		}
	}
}

func oracleSplit(s Server) (allowed []string, skipped []Skipped) {
	unique := slices.Clone(s.ApprovedTools)
	slices.Sort(unique)
	unique = slices.Compact(unique)
	for _, name := range unique {
		if oracleAllowed(name) {
			allowed = append(allowed, name)
		} else {
			skipped = append(skipped, Skipped{Server: s.Name, Tool: name})
		}
	}
	return allowed, skipped
}

func TestPropertyShuffledInputGivesIdenticalOutput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		servers := drawServers(t)
		seed := rapid.Uint64().Draw(t, "seed")
		want, err := AgentGateway(Input{ListenPort: testListenPort, Servers: servers})
		if err != nil {
			t.Fatal(err)
		}
		rng := rand.New(rand.NewPCG(seed, seed))
		shuffled := make([]Server, len(servers))
		for i, s := range servers {
			s.ApprovedTools = slices.Clone(s.ApprovedTools)
			rng.Shuffle(len(s.ApprovedTools), func(a, b int) { s.ApprovedTools[a], s.ApprovedTools[b] = s.ApprovedTools[b], s.ApprovedTools[a] })
			shuffled[i] = s
		}
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got, err := AgentGateway(Input{ListenPort: testListenPort, Servers: shuffled})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.YAML, want.YAML) || got.BodyHash != want.BodyHash {
			t.Fatalf("shuffling changed the output")
		}
	})
}

// fataler is the slice of testing.TB that both *testing.T and *rapid.T offer.
type fataler interface {
	Fatalf(format string, args ...any)
}

// splitRoutes returns the text of each route block, in file order.
func splitRoutes(yaml string) []string {
	var routes []string
	for _, line := range strings.Split(yaml, "\n") {
		if strings.HasPrefix(line, routeLinePrefix) {
			routes = append(routes, "")
		}
		if len(routes) > 0 {
			routes[len(routes)-1] += line + "\n"
		}
	}
	return routes
}

// decodeAllow extracts the tool names from the single allow rule of a route
// block, or returns nil for the never-matching rule. It fails the test if the
// route does not have exactly one allow line.
func decodeAllow(t fataler, route string) []string {
	var exprs []string
	for _, line := range strings.Split(route, "\n") {
		if strings.HasPrefix(line, allowLinePrefix) {
			exprs = append(exprs, strings.TrimPrefix(line, allowLinePrefix))
		}
	}
	if len(exprs) != 1 {
		t.Fatalf("route has %d allow rules, want exactly 1:\n%s", len(exprs), route)
	}
	var expr string
	if err := json.Unmarshal([]byte(exprs[0]), &expr); err != nil {
		t.Fatalf("allow scalar is not a valid quoted string: %v (%s)", err, exprs[0])
	}
	if expr == "false" {
		return nil
	}
	names, err := parseDisjunction(expr)
	if err != nil {
		t.Fatalf("allow expression %q does not parse: %v", expr, err)
	}
	if len(names) == 0 {
		t.Fatalf("allow expression %q names no tool", expr)
	}
	return names
}

// decodeSecret returns the secret carried by the route's single metadata line
// after undoing both quoting layers, or "" when the route has none.
func decodeSecret(t fataler, route string) string {
	var scalars []string
	for _, line := range strings.Split(route, "\n") {
		if strings.HasPrefix(line, secretLinePrefix) {
			scalars = append(scalars, strings.TrimPrefix(line, secretLinePrefix))
		}
	}
	if len(scalars) == 0 {
		return ""
	}
	if len(scalars) != 1 {
		t.Fatalf("route has %d secret lines, want at most 1:\n%s", len(scalars), route)
	}
	var cel string
	if err := json.Unmarshal([]byte(scalars[0]), &cel); err != nil {
		t.Fatalf("secret scalar is not a valid quoted string: %v (%s)", err, scalars[0])
	}
	body, ok := strings.CutPrefix(cel, `"`)
	if !ok {
		t.Fatalf("secret %q is not a CEL string literal", cel)
	}
	secret, rest, err := readCELString(body)
	if err != nil || rest != "" {
		t.Fatalf("secret literal %q does not parse cleanly: %v (rest %q)", cel, err, rest)
	}
	return secret
}

// parseDisjunction is a strict reader for exactly the grammar the emitter
// writes: mcp.tool.name == "<lit>" joined by " || ". Anything else is an error,
// so an escape bug that smuggled in extra CEL would fail here.
func parseDisjunction(expr string) ([]string, error) {
	const term = `mcp.tool.name == "`
	var names []string
	rest := expr
	for {
		if !strings.HasPrefix(rest, term) {
			return nil, fmt.Errorf("expected %q at %q", term, rest)
		}
		name, after, err := readCELString(rest[len(term):])
		if err != nil {
			return nil, err
		}
		names = append(names, name)
		if after == "" {
			return names, nil
		}
		if !strings.HasPrefix(after, " || ") {
			return nil, fmt.Errorf("expected ' || ' at %q", after)
		}
		rest = after[len(" || "):]
	}
}

// readCELString reads a CEL string body up to the closing quote and returns
// the decoded value and the text after the quote.
func readCELString(s string) (string, string, error) {
	var out strings.Builder
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '"':
			return out.String(), s[i+1:], nil
		case c != '\\':
			out.WriteByte(c)
			i++
		case i+1 < len(s) && (s[i+1] == '\\' || s[i+1] == '"'):
			out.WriteByte(s[i+1])
			i += 2
		case i+1 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U'):
			digits := map[byte]int{'u': 4, 'U': 8}[s[i+1]]
			if i+2+digits > len(s) {
				return "", "", fmt.Errorf("short unicode escape")
			}
			v, err := strconv.ParseUint(s[i+2:i+2+digits], 16, 32)
			if err != nil {
				return "", "", err
			}
			out.WriteRune(rune(v))
			i += 2 + digits
		default:
			return "", "", fmt.Errorf("unknown escape at %q", s[i:])
		}
	}
	return "", "", fmt.Errorf("unterminated string")
}

func TestParseDisjunctionRejectsExtraSyntax(t *testing.T) {
	for _, bad := range []string{
		``, `true`, `mcp.tool.name == "a" || true`, `mcp.tool.name == "a"x`, `mcp.tool.name == "a`, `mcp.tool.name == "\q"`, `mcp.tool.name == "\u00"`,
	} {
		if _, err := parseDisjunction(bad); err == nil {
			t.Errorf("parseDisjunction(%q) accepted", bad)
		}
	}
}
