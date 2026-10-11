package catalog

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// cp builds a string from code points at run time, so no test source holds an
// invisible or format character literally.
func cp(runes ...rune) string {
	var b strings.Builder
	for _, r := range runes {
		b.WriteRune(r)
	}
	return b.String()
}

// Code points the tests build hostile text from.
const (
	zwsp        = 0x200B // zero width space (Cf)
	zwj         = 0x200D // zero width joiner (Cf)
	rlo         = 0x202E // right-to-left override (Cf)
	bom         = 0xFEFF // byte order mark (Cf)
	nbsp        = 0x00A0 // no-break space (Zs)
	ideoSpace   = 0x3000 // ideographic space (Zs)
	lineSep     = 0x2028 // line separator (Zl)
	paraSep     = 0x2029 // paragraph separator (Zp)
	privateUse  = 0xE000 // private use (Co)
	vs16        = 0xFE0F // variation selector 16 (Mn)
	cgj         = 0x034F // combining grapheme joiner (Mn)
	vs17        = 0xE0100
	hangulFill  = 0x3164 // renders blank
	brailleBlnk = 0x2800 // renders blank
	choseongFil = 0x115F // renders blank
	acuteMark   = 0x0301 // combining acute: "e" + this is the NFD form of e-acute
	eAcute      = 0x00E9
)

// Server names follow the gateway's own rule for an MCP target name (review
// finding: agentgateway v1.6.0 refuses '_' and a trailing '-', and with them
// the whole emitted file). Dots are refused on purpose; see validateServerName.
func TestValidateServerName(t *testing.T) {
	long63 := "a" + strings.Repeat("b", 62)
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"a", true}, {"0", true}, {"99", true}, {"my-server-1", true}, {"a--b", true}, {"a-" + strings.Repeat("b", 60) + "c", true}, {long63, true},
		{"", false}, {"-", false}, {"-a", false}, {"a-", false}, {"_a", false}, {"a_", false}, {"my_server", false}, {"my-server_1", false},
		{"A", false}, {"a b", false}, {"a.b", false}, {"a.", false}, {".", false}, {"..", false},
		{"a/b", false}, {"a\n", false}, {"a\x00", false}, {cp(eAcute), false}, {long63 + "c", false},
		{"a'; DROP TABLE servers; --", false}, {"../etc", false},
	} {
		err := validateServerName(tc.name)
		if tc.ok != (err == nil) {
			t.Errorf("validateServerName(%q) = %v, want ok=%t", tc.name, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("validateServerName(%q) error %v is not ErrInvalid", tc.name, err)
		}
	}
}

func TestValidateURL(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", maxURLBytes)
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://example.com/mcp", true},
		{"http://localhost:8080/mcp", true},
		{"HTTPS://Example.com/mcp?x=1", true},
		{"http://[::1]:9000/", true},
		{"https://example.com:65535/", true},
		{"", false},
		{long, false},
		{"ftp://example.com/", false},
		{"file:///etc/passwd", false},
		{"javascript:alert(1)", false},
		{"//example.com/mcp", false},
		{"example.com/mcp", false},
		{"https:///path", false},
		{"https://user:pw@example.com/", false},
		{"https://user@example.com/", false},
		{"https://example.com/#frag", false},
		{"https://example.com/#", false},
		{"https://example.com:0/", false},
		{"https://example.com:99999/", false},
		{"https://example.com/a b", false},
		{"https://example.com/\x00", false},
		{"https://example.com/\n", false},
		{"https://exa\\mple.com/", false},
		{"https://example.com/" + cp(eAcute), false},
		{"https:opaque", false},
		// The characters the gateway's URI parser refuses (review finding), and
		// everything else outside the RFC 3986 reserved and unreserved sets.
		{"https://example.com/mcp?x=\"y\"", false},
		{"https://example.com/<mcp>", false},
		{"https://example.com/a|b", false},
		{"https://example.com/a^b", false},
		{"https://example.com/{mcp}", false},
		{"https://example.com/`mcp`", false},
		{"https://example.com/\x7f", false},
		{"https://example.com/a\tb", false},
		// The RFC 3986 unreserved marks, sub-delims and percent-encoding stay allowed.
		{"https://example.com/a~b_(c)*,;=!$&'+/-.", true},
		{"https://example.com/%41%2Fmcp?x=1&y=2@3:4", true},
	} {
		err := validateURL(tc.url)
		if tc.ok != (err == nil) {
			t.Errorf("validateURL(%.60q) = %v, want ok=%t", tc.url, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("validateURL(%.60q) error %v is not ErrInvalid", tc.url, err)
		}
	}
}

// D7: actor names are identifiers, normalised before storage and comparison.
func TestNormalizeActor(t *testing.T) {
	for _, tc := range []struct {
		actor Actor
		want  string // "" means refused
	}{
		{Actor{"alice", ActorHuman}, "alice"},
		{Actor{"Alice", ActorHuman}, "alice"},
		{Actor{"ALICE", ActorHuman}, "alice"},
		{Actor{"ci-bot_2", ActorSystem}, "ci-bot_2"},
		{Actor{"jose@example.com", ActorHuman}, "jose@example.com"},
		{Actor{"a", ActorHuman}, "a"},
		{Actor{"a" + strings.Repeat("b", 63), ActorHuman}, "a" + strings.Repeat("b", 63)},
		// NFKC folds full-width letters, the Kelvin sign and ligatures onto their ASCII forms.
		{Actor{cp(0xFF21, 0xFF2C, 0xFF29, 0xFF23, 0xFF25), ActorHuman}, "alice"},
		{Actor{cp(0x212A) + "elvin", ActorHuman}, "kelvin"},
		{Actor{cp(0xFB01) + "ona", ActorHuman}, "fiona"},
		{Actor{"", ActorHuman}, ""},
		{Actor{"alice", ""}, ""},
		{Actor{"alice", "robot"}, ""},
		{Actor{" alice", ActorHuman}, ""},
		{Actor{"alice ", ActorHuman}, ""},
		{Actor{"ci bot", ActorSystem}, ""},
		{Actor{"al\tice", ActorHuman}, ""},
		{Actor{"al" + cp(zwsp) + "ice", ActorHuman}, ""},
		{Actor{"alice\n", ActorHuman}, ""},
		{Actor{"jos" + cp(eAcute), ActorHuman}, ""},
		{Actor{"rene" + cp(acuteMark), ActorHuman}, ""},
		{Actor{"-alice", ActorHuman}, ""},
		{Actor{".alice", ActorHuman}, ""},
		{Actor{"a" + strings.Repeat("b", 64), ActorHuman}, ""},
		{Actor{strings.Repeat("a", maxActorNameBytes+1), ActorHuman}, ""},
		{Actor{"bad\xffutf8", ActorHuman}, ""},
	} {
		got, err := normalizeActor(tc.actor)
		if (tc.want == "") != (err != nil) || got.Name != tc.want {
			t.Errorf("normalizeActor(%q, %q) = %+v, %v; want name %q", tc.actor.Name, tc.actor.Type, got, err, tc.want)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeActor(%q) error %v is not ErrInvalid", tc.actor.Name, err)
		}
		if err == nil && got.Type != tc.actor.Type {
			t.Errorf("normalizeActor changed the type: %+v", got)
		}
	}
}

// Tool names follow internal/toolname: the rule every component shares.
func TestValidateToolName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"echo", true}, {"with space", true}, {"snake_case-and.dots", true}, {cp(0x65E5, 0x672C, 0x8A9E), true},
		{"emoji" + cp(0x1F600), true}, {"caf" + cp(eAcute), true}, {strings.Repeat("a", maxToolNameBytes), true},
		{"", false},
		{strings.Repeat("a", maxToolNameBytes+1), false},
		{"tab\there", false},
		{"new\nline", false},
		{"nul\x00byte", false},
		{"del\x7f", false},
		{"zero" + cp(zwsp) + "width", false},
		{"joiner" + cp(zwj) + "x", false},
		{"bidi" + cp(rlo) + "evil", false},
		{"bom" + cp(bom) + "x", false},
		{"nbsp" + cp(nbsp) + "x", false},
		{"ideographic" + cp(ideoSpace) + "x", false},
		{"line" + cp(lineSep) + "sep", false},
		{"para" + cp(paraSep) + "sep", false},
		{"private" + cp(privateUse) + "use", false},
		{"bad\xc3\x28utf8", false},
		{"surrogate\xed\xa0\x80", false}, // Cs encoded in UTF-8 is invalid UTF-8
		// The look-alikes the first filter let through.
		{"echo" + cp(vs16), false},
		{"ec" + cp(cgj) + "ho", false},
		{"echo" + cp(vs17), false},
		{"echo" + cp(hangulFill), false},
		{"echo" + cp(brailleBlnk), false},
		{"echo" + cp(choseongFil), false},
		{"cafe" + cp(acuteMark), false}, // NFD, not NFC
		{"echo ", false},
		{" echo", false},
		{"ec  ho", false},
	} {
		err := validateToolName(tc.name)
		if tc.ok != (err == nil) {
			t.Errorf("validateToolName(%q) = %v, want ok=%t", tc.name, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("validateToolName(%q) error %v is not ErrInvalid", tc.name, err)
		}
		if err != nil && len(tc.name) > 4 && strings.Contains(err.Error(), tc.name) {
			t.Errorf("validateToolName(%q) echoed the name: %v", tc.name, err)
		}
	}
}

// maxToolNameBytes mirrors toolname.MaxBytes for the table above.
const maxToolNameBytes = 256

func TestNormalizeDigestAndPrefix(t *testing.T) {
	full := strings.Repeat("ab12", 16)
	if got, err := normalizeDigest(strings.ToUpper(full)); err != nil || got != full {
		t.Errorf("normalizeDigest(upper) = %q, %v", got, err)
	}
	for _, bad := range []string{"", "abc", full[:63], full + "0", strings.Repeat("g", 64), " " + full[1:]} {
		if _, err := normalizeDigest(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeDigest(%.20q) = %v, want ErrInvalid", bad, err)
		}
	}
	if got, err := normalizePrefix("ABCDEF12"); err != nil || got != "abcdef12" {
		t.Errorf("normalizePrefix = %q, %v", got, err)
	}
	for _, bad := range []string{"", "abcdef1", strings.Repeat("a", 65), "abcdefgh", "abcdef1%"} {
		if _, err := normalizePrefix(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizePrefix(%q) = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestSanitizeTextAndClasses(t *testing.T) {
	if got := sanitizeText("a\nb\tc\x00d"+cp(zwsp)+"e", 100); got != "a b c?d?e" {
		t.Errorf("sanitizeText = %q", got)
	}
	if got := sanitizeText("bad\xffbyte", 100); got != "bad?byte" {
		t.Errorf("invalid UTF-8: %q", got)
	}
	// Cutting must land on a rune boundary.
	cut := sanitizeText(strings.Repeat(cp(eAcute), 10), 5)
	if !utf8.ValidString(cut) || len(cut) > 5 {
		t.Errorf("cut = %q (%d bytes)", cut, len(cut))
	}
	if got := quote(strings.Repeat("x", 500)); len(got) > maxQuotedBytes+8 {
		t.Errorf("quote did not truncate: %d bytes", len(got))
	}
	for in, want := range map[string]string{
		"timeout": "timeout", "not-canonical": "not-canonical", " Too-Large ": "too-large", "a.b_c-1": "a.b_c-1",
		"http status 401": "http status 401", "dns lookup failed": "dns lookup failed", "Unknown Error": "unknown error",
		"": "error", "get https://x: timeout": "error", "-x": "error", "Tool \"x\"": "error", "two  spaces": "error",
		"tab\tsplit": "error", "bidi" + cp(rlo) + "x": "error", strings.Repeat("a", maxClassLen+1): "error",
	} {
		if got := errorClass(in); got != want {
			t.Errorf("errorClass(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"timeout": "timeout", "": "",
		"get https://host/?t=S: boom\n\x00": `error "get https://host/?t=S: boom ?"`,
		"bidi" + cp(rlo) + "evil":           `error "bidi?evil"`,
	} {
		if got := crawlErrorRecord(in, ""); got != want {
			t.Errorf("crawlErrorRecord(%q) = %q, want %q", in, got, want)
		}
	}
	if got := crawlErrorRecord("anything", failureTooLarge); got != failureTooLarge {
		t.Errorf("a whole-crawl failure class wins: %q", got)
	}
	if got := auditClass("http status 401"); got != `"http status 401"` {
		t.Errorf("auditClass(phrase) = %s", got)
	}
	if got := auditClass("timeout"); got != "timeout" {
		t.Errorf("auditClass(token) = %s", got)
	}
}
