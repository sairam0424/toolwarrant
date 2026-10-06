package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/crawl"
	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestCellEscapesEverythingATerminalWouldObey(t *testing.T) {
	cases := map[string]string{
		"":                emptyCell,
		"plain":           "plain",
		"a​b":             `a\u{200B}b`,
		"a\x1b[31mb":      `a\u{001B}[31mb`,
		"a‮b":             `a\u{202E}b`,
		"line\nbreak":     `line\u{000A}break`,
		`back\slash`:      `back\\slash`,
		"tab\there":       `tab\there`,
		"café":            "café",
		"bad\xffbyte":     `bad\x{FF}byte`,
		`\u{000A}` + "\n": `\\u{000A}\u{000A}`,
	}
	for in, want := range cases {
		if got := cell(in); got != want {
			t.Errorf("cell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShortDigest(t *testing.T) {
	full := strings.Repeat("ab", 32)
	if got := shortDigest(full); got != "abababababab" {
		t.Errorf("shortDigest = %q", got)
	}
	if got := shortDigest("abc"); got != "abc" {
		t.Errorf("short input = %q", got)
	}
	if got := shortDigest(""); got != emptyCell {
		t.Errorf("empty = %q", got)
	}
}

func TestSafeURLKeepsOnlySchemeHostAndPath(t *testing.T) {
	cases := map[string]string{
		"http://user:pw@host:8080/mcp?token=x#frag": "http://host:8080/mcp",
		"https://example.com/":                      "https://example.com/",
		"https://example.com":                       "https://example.com",
		"http://127.0.0.1:3001/a/b?x=1":             "http://127.0.0.1:3001/a/b",
		"not a url":                                 invalidURL,
		"":                                          invalidURL,
		"/relative/only":                            invalidURL,
	}
	for in, want := range cases {
		if got := safeURL(in); got != want {
			t.Errorf("safeURL(%q) = %q, want %q", in, got, want)
		}
	}
	// A path is re-encoded, so an invisible character cannot reach the terminal
	// raw either way; the escape step still guards the host.
	if got := displayURL("http://h/​p"); strings.Contains(got, "​") || !strings.Contains(got, "%E2%80%8B") {
		t.Errorf("displayURL left the path unsafe: %q", got)
	}
	if got := displayURL("http://h\x1b/p"); strings.Contains(got, "\x1b") {
		t.Errorf("displayURL leaked a control character: %q", got)
	}
}

func TestShellWordQuotesOnlyWhenNeeded(t *testing.T) {
	cases := map[string]string{
		"/tmp/tw.db":     "/tmp/tw.db",
		"127.0.0.1:9001": "127.0.0.1:9001",
		"with space.db":  "'with space.db'",
		"it's":           `'it'\''s'`,
		"semi;colon":     "'semi;colon'",
	}
	for in, want := range cases {
		if got := shellWord(in); got != want {
			t.Errorf("shellWord(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseArgsAcceptsFlagsAnywhere(t *testing.T) {
	a := &app{}
	c := &command{name: "x", synopsis: "x"}
	parse := func(args ...string) ([]string, string, error) {
		fs := newFlagSet("x")
		v := fs.String("v", "", "")
		pos, err := a.parseArgs(c, fs, args)
		return pos, *v, err
	}
	pos, v, err := parse("a", "b", "--v", "1")
	if err != nil || v != "1" || strings.Join(pos, ",") != "a,b" {
		t.Errorf("trailing flag: %v %q %v", pos, v, err)
	}
	pos, v, err = parse("--v", "2", "a", "--", "-b")
	if err != nil || v != "2" || strings.Join(pos, ",") != "a,-b" {
		t.Errorf("terminator: %v %q %v", pos, v, err)
	}
	pos, _, err = parse("--")
	if err != nil || len(pos) != 0 {
		t.Errorf("lone terminator: %v %v", pos, err)
	}
	_, _, err = parse("a", "--nope")
	var ue *usageError
	if !errors.As(err, &ue) || ue.cmd != c {
		t.Errorf("unknown flag: %v", err)
	}
	_, _, err = parse("-h")
	var he *helpError
	if !errors.As(err, &he) || !strings.Contains(he.text, "usage: toolwarrant [global flags] x") {
		t.Errorf("help: %v", err)
	}
	if err := wantArgs(c, []string{"a"}, "A", "B"); err == nil {
		t.Error("wantArgs accepted the wrong count")
	}
	fs := flag.NewFlagSet("y", flag.ContinueOnError)
	if !strings.Contains(c.usage(fs), c.synopsis) || strings.Contains(c.usage(fs), "flags:") {
		t.Errorf("usage without flags = %q", c.usage(fs))
	}
}

func TestDescribeMapsSentinelsToAdvice(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("catalog: approve: %w", err) }
	cases := []struct {
		err  error
		want string
	}{
		{wrap(lifecycle.ErrSelfApproval), adviceSelfApproval},
		{wrap(lifecycle.ErrStaleVersion), adviceStale},
		{wrap(lifecycle.ErrInvalidTransition), "run show"},
		{wrap(lifecycle.ErrNotRollbackTarget), "approved before"},
		{wrap(catalog.ErrAmbiguous), adviceAmbiguous},
		{wrap(catalog.ErrNotFound), "not found"},
		{wrap(catalog.ErrExists), "already exists"},
		{wrap(catalog.ErrInvalid), "invalid input"},
		{wrap(catalog.ErrSchema), "upgrade toolwarrant"},
		{wrap(catalog.ErrCorrupt), "do not serve"},
		{&audit.BrokenError{Seq: 7, Reason: "hash mismatch"}, "broken at entry 7"},
		{wrap(emit.ErrInvalidInput), "emit again"},
		{context.Canceled, "interrupted"},
		{wrap(fetch.ErrBlockedAddress), "--allow-private"},
		{wrap(fetch.ErrBlockedHost), "user info"},
		{wrap(fetch.ErrBlockedScheme), "http and https"},
		{wrap(fetch.ErrRedirect), "redirect"},
		{wrap(fetch.ErrTooLarge), "size cap"},
		{errors.New("plain \x1b[31m text"), `plain \u{001B}[31m text`},
	}
	for _, tc := range cases {
		if got := describe(tc.err); !strings.Contains(got, tc.want) {
			t.Errorf("describe(%v) = %q, want it to contain %q", tc.err, got, tc.want)
		}
	}
}

func TestScrubCrawlErrorNeverLeaksText(t *testing.T) {
	secret := "http://host/mcp?token=SECRET"
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("initialize: %w", &crawl.HTTPStatusError{Status: 403}), "http status 403"},
		{&crawl.RPCError{Code: -32600, Message: secret}, "json-rpc error -32600"},
		{fmt.Errorf("%w: %s", fetch.ErrBlockedAddress, secret), "egress policy: address not allowed"},
		{fmt.Errorf("%w: %s", fetch.ErrBlockedHost, secret), "egress policy: host not allowed"},
		{fetch.ErrBlockedScheme, "egress policy: scheme not allowed"},
		{fetch.ErrRedirect, "egress policy: redirect refused"},
		{fetch.ErrTooLarge, "response too large"},
		{crawl.ErrTooManyPages, "too many pages"},
		{crawl.ErrTooManyTools, "too many tools"},
		{crawl.ErrCursorLoop, "pagination cursor loop"},
		{crawl.ErrDuplicateTool, "duplicate tool name"},
		{fmt.Errorf("%w: %s", crawl.ErrMalformed, secret), "malformed server response"},
		{crawl.ErrInvalidOptions, "invalid crawl options"},
		{&url.Error{Op: "Post", URL: secret, Err: context.DeadlineExceeded}, classTimeout},
		{context.Canceled, classCancelled},
		{&net.DNSError{Err: "no such host", Name: "host"}, classDNS},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, classRefused},
		{&net.OpError{Op: "dial", Err: errors.New("network unreachable")}, classConnection},
		{errors.New(secret), classUnknown},
	}
	for _, tc := range cases {
		got := scrubCrawlError(tc.err)
		if got != tc.want {
			t.Errorf("scrub(%v) = %q, want %q", tc.err, got, tc.want)
		}
		if strings.Contains(got, "SECRET") || strings.Contains(got, "token") {
			t.Errorf("scrub leaked: %q", got)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.5.4.3": true, "::1": true, "localhost": true, "LOCALHOST": true,
		"": false, "0.0.0.0": false, "::": false, "10.0.0.1": false, "example.com": false, "fe80::1%lo0": false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestNormalizeActorName(t *testing.T) {
	for in, want := range map[string]string{"Alice": "alice", "a.b_c@d-e": "a.b_c@d-e", "X": "x"} {
		got, err := normalizeActorName(in)
		if err != nil || got != want {
			t.Errorf("normalize(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", ".dot", "has space", "ali​ce", strings.Repeat("a", 65), "semi;colon"} {
		if _, err := normalizeActorName(bad); err == nil {
			t.Errorf("normalize(%q) accepted", bad)
		}
	}
}

func TestSummarizeAndFlags(t *testing.T) {
	changes := []catalog.ToolChange{
		{Tool: "a", Kind: catalog.ChangeNew, State: lifecycle.PendingReview},
		{Tool: "b", Kind: catalog.ChangeChanged, State: lifecycle.ChangedPendingReapproval},
		{Tool: "c", Kind: catalog.ChangeUnchanged, State: lifecycle.Enabled},
	}
	if got := summarize(changes); got != "new=1 changed=1 unchanged=1" {
		t.Errorf("summarize = %q", got)
	}
	if got := summarize(nil); got != "no changes" {
		t.Errorf("summarize(nil) = %q", got)
	}
	if changeLabel(changes[0]) != "NEW" || changeLabel(changes[2]) != "unchanged" || driftFlag(changes[1]) != flagDrift || driftFlag(changes[0]) != "" {
		t.Error("labels or drift flag wrong")
	}
	v := catalog.ToolView{Drifted: true, MissingCrawls: 2}
	if got := toolFlags(v); got != flagDrift+","+flagMissing {
		t.Errorf("toolFlags = %q", got)
	}
	if got := toolFlags(catalog.ToolView{}); got != "" {
		t.Errorf("toolFlags(zero) = %q", got)
	}
}

func TestWalkStringsFindsHiddenCharactersWithPaths(t *testing.T) {
	doc := []byte(`{"name":"t","description":"a​b","inputSchema":{"properties":{"x‮":{"description":"ok"}}},"list":["\u001b[31m"]}`)
	found, err := scanStrings(doc)
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(found))
	for _, f := range found {
		paths = append(paths, fmt.Sprintf("%s:%04X", f.path, f.Rune))
	}
	want := []string{"$.description:200B", "$.inputSchema.properties.x‮ (key):202E", "$.list[0]:001B"}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Errorf("findings = %v, want %v", paths, want)
	}
	if _, err := scanStrings([]byte("not json")); err == nil {
		t.Error("scanStrings accepted garbage")
	}
	if found, _ := scanStrings([]byte(`{"name":"clean","n":1,"b":true,"z":null}`)); len(found) != 0 {
		t.Errorf("clean document reported %v", found)
	}
}

func TestCompareServed(t *testing.T) {
	approved := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	snap := catalog.Snapshot{Server: "s1", Tools: map[string]catalog.ToolPolicy{
		"served":   {State: lifecycle.Enabled, Approved: approved, LastSeen: approved},
		"drifted":  {State: lifecycle.ChangedPendingReapproval, Approved: approved, LastSeen: other},
		"disabled": {State: lifecycle.Disabled, Approved: approved, LastSeen: approved},
	}}
	live := []liveTool{{"served", approved}, {"drifted", other}, {"unknown", other}, {"broken", ""}}
	leaks, missing := compareServed(snap, live)
	if len(leaks) != 3 || leaks[0].name != "drifted" || leaks[1].name != "unknown" || leaks[2].name != "broken" {
		t.Errorf("leaks = %+v", leaks)
	}
	if len(missing) != 0 {
		t.Errorf("missing = %v", missing)
	}
	leaks, missing = compareServed(snap, nil)
	if len(leaks) != 0 || strings.Join(missing, ",") != "served" {
		t.Errorf("empty gateway: leaks %v missing %v", leaks, missing)
	}
}

func TestProcessorOverridesFlag(t *testing.T) {
	p := processorOverrides{}
	if err := p.Set("s1=127.0.0.1:9001"); err != nil {
		t.Fatal(err)
	}
	if err := p.Set("s1=127.0.0.1:9002"); err == nil {
		t.Error("duplicate accepted")
	}
	for _, bad := range []string{"", "s1", "=x", "s1="} {
		if err := p.Set(bad); err == nil {
			t.Errorf("Set(%q) accepted", bad)
		}
	}
	if p.String() != "s1=127.0.0.1:9001" {
		t.Errorf("String = %q", p.String())
	}
}
