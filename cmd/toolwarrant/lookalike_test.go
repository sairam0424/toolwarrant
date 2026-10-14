package main

import (
	"testing"
)

// Every look-alike in this file is a \u escape (JSON escapes inside the raw
// schema strings, Go escapes elsewhere), so the source holds no character that
// reads as another; the crawler's canonical form carries the decoded runes.
const (
	// copySchemaCyrillicPath spells the path parameter with a Cyrillic a
	// (U+0430) in the property name and in the required list.
	copySchemaCyrillicPath = `{"type":"object","properties":{"pаth":{"type":"string"}},"required":["pаth"]}`
	cyrillicAText          = "а"
	cyrillicCapitalA       = "А"
	cyrillicOText          = "о"
	// Japanese, Korean and Chinese descriptions with a Latin acronym: the UTS
	// #39 Highly Restrictive profile allows each combination.
	tokyoDescription  = "東京のAPIを呼ぶ"
	osakaDescription  = "大阪のAPIを呼ぶ"
	seoulDescription  = "한국API 호출"
	taipeiDescription = "ㄅㄆAPI 台北"
)

// A parameter renamed to a look-alike of the approved one is invisible in the
// diff: the review names the swapped code points against the approved version
// and refuses, the state is unchanged, diff shows the same section, and the
// flag approves it with a warning.
func TestApproveRefusesALookAlikeSwapUnlessAccepted(t *testing.T) {
	c, u := copyFixture(t)
	v1 := c.tool("s1", "copy").Pending
	c.approve("alice", "s1", "copy", v1)
	u.setTool(schemaTool(copyDescription, copySchemaCyrillicPath))
	c.ok("crawl", "s1")
	v2 := c.tool("s1", "copy").Pending

	r := c.fail(exitFailure, "--as", "alice", "approve", "s1", "copy", "--hash", v2)
	wantContains(t, "stderr", r.stderr,
		"look-alike changes against the approved version 1:",
		"  $.inputSchema.properties[\"p"+cyrillicAText+"th\"] (key): U+0430 (Cyrillic) for U+0061 (Latin) at byte 1\n",
		"  $.inputSchema.required[0]: U+0430 (Cyrillic) for U+0061 (Latin) at byte 1\n",
		"mixed-script words in this definition:",
		"  $.inputSchema.properties.p"+cyrillicAText+"th (key) byte 0: Cyrillic (U+0430) with Latin (U+0070 U+0074 U+0068)\n",
		"  $.inputSchema.required[0] byte 0: Cyrillic (U+0430) with Latin (U+0070 U+0074 U+0068)\n",
		"refusing to approve: the definition holds 2 mixed-script word(s) and 2 look-alike change(s), listed above", "--accept-suspicious")
	wantNotContains(t, "stderr", r.stderr, "suspicious characters in this definition")
	if tv := c.tool("s1", "copy"); tv.Approved != v1 {
		t.Fatalf("a refused approval must change nothing: %+v", tv.toolJSON)
	}

	out := c.ok("diff", "s1", "copy")
	wantContains(t, "diff", out, "Look-alike changes\n  4 (look-alike: 2, mixed-script: 2)\n",
		"U+0430 (Cyrillic) for U+0061 (Latin) at byte 1 (look-alike)",
		"Cyrillic (U+0430) with Latin (U+0070 U+0074 U+0068) (mixed-script)")

	r = c.run("--as", "alice", "approve", "s1", "copy", "--hash", v2, "--accept-suspicious")
	if r.code != exitOK {
		t.Fatalf("approve --accept-suspicious: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "warning: approving despite 2 mixed-script word(s) and 2 look-alike change(s)\n")
	wantContains(t, "stdout", r.stdout, "approved s1/copy at "+v2)
	if tv := c.tool("s1", "copy"); tv.Approved != v2 || tv.State != "enabled" {
		t.Fatalf("after the accepted approval: %+v", tv.toolJSON)
	}
}

// A first approval has no approved version to compare with, so look-alike
// swaps cannot be found; a word that mixes scripts is found on its own and
// refused the same way, with the code points and never the characters.
func TestApproveRefusesMixedScriptWordsUnlessAccepted(t *testing.T) {
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"fetch": "Fetch the " + cyrillicCapitalA + "PI t" + cyrillicOText + "ken."})
	c.ok("server", "add", "s1", u.url(), "--allow-private")
	c.ok("crawl", "s1")
	v := c.tool("s1", "fetch").Pending

	r := c.fail(exitFailure, "--as", "alice", "approve", "s1", "fetch", "--hash", v)
	wantContains(t, "stderr", r.stderr,
		"mixed-script words in this definition:\n",
		"  $.description byte 10: Cyrillic (U+0410) with Latin (U+0050 U+0049)\n",
		"  $.description byte 15: Cyrillic (U+043E) with Latin (U+0074 U+006B U+0065 U+006E)\n",
		"refusing to approve: the definition holds 2 mixed-script word(s), listed above", "--accept-suspicious")
	wantNotContains(t, "stderr", r.stderr, cyrillicCapitalA, cyrillicOText, "look-alike changes", "suspicious characters in this definition")
	if tv := c.tool("s1", "fetch"); tv.State != "pending_review" {
		t.Fatalf("a refused approval must change nothing: %+v", tv.toolJSON)
	}

	r = c.run("--as", "alice", "approve", "s1", "fetch", "--hash", v, "--accept-suspicious")
	if r.code != exitOK {
		t.Fatalf("approve --accept-suspicious: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "warning: approving despite 2 mixed-script word(s)\n")
	wantNotContains(t, "stderr", r.stderr, cyrillicCapitalA, cyrillicOText)
	if tv := c.tool("s1", "fetch"); tv.State != "enabled" {
		t.Fatalf("after the accepted approval: %+v", tv.toolJSON)
	}
}

// Japanese, Korean and Chinese text with a Latin acronym is one of the UTS #39
// Highly Restrictive combinations: approved without the flag and without a
// word of warning, and so is a later version whose change is visible.
func TestApproveAcceptsCJKWithLatinAcronyms(t *testing.T) {
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"tokyo": tokyoDescription, "seoul": seoulDescription, "taipei": taipeiDescription})
	c.ok("server", "add", "s1", u.url(), "--allow-private")
	c.ok("crawl", "s1")
	for _, name := range []string{"tokyo", "seoul", "taipei"} {
		v := c.tool("s1", name).Pending
		r := c.run("--as", "alice", "approve", "s1", name, "--hash", v)
		if r.code != exitOK {
			t.Fatalf("approve %s: exit %d: %s", name, r.code, r.stderr)
		}
		wantNotContains(t, name+" stderr", r.stderr, "mixed-script", "look-alike", "suspicious", "warning")
		if tv := c.tool("s1", name); tv.State != "enabled" || tv.Approved != v {
			t.Fatalf("%s after approval: %+v", name, tv.toolJSON)
		}
	}

	u.set("tokyo", osakaDescription)
	c.ok("crawl", "s1")
	v2 := c.tool("s1", "tokyo").Pending
	r := c.run("--as", "alice", "approve", "s1", "tokyo", "--hash", v2)
	if r.code != exitOK {
		t.Fatalf("approve the visible change: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, changePrefix+"1: WARNING (description-changed)\n")
	wantNotContains(t, "stderr", r.stderr, "mixed-script", "look-alike", "suspicious", "warning")
	if tv := c.tool("s1", "tokyo"); tv.Approved != v2 {
		t.Fatalf("after approving the visible change: %+v", tv.toolJSON)
	}
}
