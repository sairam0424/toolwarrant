package main

import (
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Decision D12: every served tool that the serving rule rejects is a LEAK and
// fails the check; MISMATCH is only the sub-label of the LEAK whose sole
// explanation is the gateway (approved, enabled, the latest crawl saw the
// approved digest); UNVERIFIED is the sub-label of the LEAK whose latest
// crawl left a marker instead of a digest (D13, lifecycle.LastSeenVerifiable),
// which is never MISSING when absent because the processor is right to hide
// it; MISSING never fails. The summary prefix is the one docs/operations.md
// quotes.
func TestCompareSortsLiveToolsIntoVerdicts(t *testing.T) {
	approved := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	snap := catalog.Snapshot{Server: "s1", Tools: map[string]catalog.ToolPolicy{
		"served":     {State: lifecycle.Enabled, Approved: approved, LastSeen: approved},
		"drifted":    {State: lifecycle.ChangedPendingReapproval, Approved: approved, LastSeen: other},
		"disabled":   {State: lifecycle.Disabled, Approved: approved, LastSeen: approved},
		"reserial":   {State: lifecycle.Enabled, Approved: approved, LastSeen: approved},
		"absent":     {State: lifecycle.Enabled, Approved: approved, LastSeen: approved},
		"gone":       {State: lifecycle.Enabled, Approved: approved, LastSeen: ""},
		"unverified": {State: lifecycle.Enabled, Approved: approved, LastSeen: lifecycle.UnusableDigest},
		"hidden":     {State: lifecycle.Enabled, Approved: approved, LastSeen: lifecycle.UnusableDigest},
	}}
	live := []liveTool{{name: "served", digest: approved}, {name: "drifted", digest: other}, {name: "unknown", digest: other},
		{name: "broken", unusable: "not-canonical"}, {name: "disabled", digest: approved}, {name: "reserial", digest: other}, {name: "unverified", digest: approved}}
	var res verdicts
	compare(snap, live, &res)
	var leaks, mismatched, unverified []string
	for _, l := range res.leaks {
		leaks = append(leaks, l.name)
		if l.mismatch {
			mismatched = append(mismatched, l.name)
		}
		if l.unverified != "" {
			unverified = append(unverified, l.name)
		}
	}
	if strings.Join(leaks, ",") != "drifted,unknown,broken,disabled,reserial,unverified" {
		t.Errorf("leaks = %v", leaks)
	}
	if strings.Join(mismatched, ",") != "reserial" || strings.Join(unverified, ",") != "unverified" {
		t.Errorf("mismatched = %v unverified = %v", mismatched, unverified)
	}
	if m, u := res.subLabelCounts(); m != 1 || u != 1 {
		t.Errorf("sub-label counts = %d %d", m, u)
	}
	if strings.Join(res.missing, ",") != "absent" || res.approvedOf("absent") != approved || res.approvedOf("gone") != "" || res.served != 1 || !res.failed() {
		t.Errorf("missing %v served %d failed %v", res.missing, res.served, res.failed())
	}
	wantContains(t, "summary", res.summary(), "the gateway serves 7 tool(s), 1 approved and current", "6 leaked (1 of them "+verdictMismatch+", 1 of them "+verdictUnverified+")", "1 approved but not listed ("+verdictMissing+")")
	wantContains(t, "mismatch line", leakLine(res.leaks[4]), verdictLeak+" reserial live "+other[:shortDigestLen]+" approved "+approved[:shortDigestLen], "("+verdictMismatch+":", "no processor")
	wantContains(t, "unverified line", leakLine(res.leaks[5]), verdictLeak+" unverified live "+approved[:shortDigestLen]+" approved "+approved[:shortDigestLen], "("+verdictUnverified+": the latest crawl left the marker "+lifecycle.UnusableDigest, "the route has no processor")
	wantNotContains(t, "drifted line", leakLine(res.leaks[0]), verdictMismatch, verdictUnverified)
	wantContains(t, "drifted line", leakLine(res.leaks[0]), verdictLeak+" drifted live "+other[:shortDigestLen]+" approved "+approved[:shortDigestLen])
	wantContains(t, "unknown line", leakLine(res.leaks[1]), verdictLeak+" unknown live "+other[:shortDigestLen])
	wantNotContains(t, "unknown line", leakLine(res.leaks[1]), "approved")
	if got := leakLine(res.leaks[2]); got != verdictLeak+" broken (unusable definition: not-canonical)" {
		t.Errorf("unusable line = %q", got)
	}

	// With the processor in place the re-serialised tool and the unverified
	// one are hidden: the first shows as MISSING (limit L2), which never
	// fails, the second is not reported at all.
	var clean verdicts
	compare(snap, []liveTool{{name: "served", digest: approved}}, &clean)
	if clean.failed() || clean.served != 1 || strings.Join(clean.missing, ",") != "absent,reserial" {
		t.Errorf("clean = %+v", clean)
	}
	wantContains(t, "clean summary", clean.summary(), "the gateway serves 1 tool(s), 1 approved and current, 2 approved but not listed ("+verdictMissing+")")
	wantNotContains(t, "clean summary", clean.summary(), "leaked", verdictMismatch, verdictUnverified)
	var onlyMismatch verdicts
	compare(snap, []liveTool{{name: "reserial", digest: other}}, &onlyMismatch)
	wantContains(t, "one sub-label", onlyMismatch.summary(), "1 leaked (1 of them "+verdictMismatch+")")
	wantNotContains(t, "one sub-label", onlyMismatch.summary(), verdictUnverified)
}

// Each of the other verdicts fails on its own, and the summary names the state
// of every check so a log line stands alone.
func TestVerdictsFailAndSummarizeEachCheck(t *testing.T) {
	for name, v := range map[string]verdicts{
		"config edited":         {configEdited: true},
		"body hash differs":     {configEdited: true, configExpected: strings.Repeat("0", 64)},
		"live config differs":   {live: liveCheck{compared: true, diffs: []string{"x"}}},
		"unhooked calls":        {probe: probeReport{outcome: probeUnhooked}},
		"inconclusive probe":    {probe: probeReport{outcome: probeInconclusive}},
		"one leak":              {leaks: []leak{{liveTool: liveTool{name: "x"}}}},
		"unreadable file":       {configEdited: true, configReason: "open: no such file"},
		"edited and unhooked":   {configEdited: true, probe: probeReport{outcome: probeUnhooked}},
		"leak with missing":     {leaks: []leak{{}}, missing: []string{"m"}},
		"live diff and missing": {live: liveCheck{compared: true, diffs: []string{"x"}}, missing: []string{"m"}},
	} {
		if !v.failed() {
			t.Errorf("%s must fail the check", name)
		}
	}
	for name, v := range map[string]verdicts{
		"nothing checked": {},
		"healthy":         {served: 2, live: liveCheck{compared: true}, probe: probeReport{outcome: probeNotAccepted, status: 400}},
		"missing only":    {missing: []string{"m"}, probe: probeReport{outcome: probeNotAccepted, status: 400}},
		"live skipped":    {live: liveCheck{skipped: "why"}},
	} {
		if v.failed() {
			t.Errorf("%s must not fail the check", name)
		}
	}
	cases := map[string]struct {
		v    verdicts
		want []string
	}{
		"default":      {verdicts{}, []string{"the gateway serves 0 tool(s), 0 approved and current", "; live configuration not compared (no --admin)", "; unhooked-call probe skipped (--no-probe)"}},
		"healthy":      {verdicts{served: 2, live: liveCheck{compared: true}, probe: probeReport{outcome: probeNotAccepted, status: 400}}, []string{"the gateway serves 2 tool(s), 2 approved and current", "; live configuration matches the emitted file", "; the id-less tools/call was not accepted as a notification (HTTP 400, by the gateway or by the upstream)"}},
		"edited":       {verdicts{configEdited: true}, []string{", configuration edited"}},
		"skipped":      {verdicts{live: liveCheck{skipped: "why"}}, []string{"; live configuration not compared (why)"}},
		"differs":      {verdicts{live: liveCheck{compared: true, diffs: []string{"x"}}}, []string{"; live configuration differs from the emitted file (" + verdictLiveConfig + ")"}},
		"unhooked":     {verdicts{probe: probeReport{outcome: probeUnhooked}}, []string{"; id-less tools/call forwarded unhooked (" + verdictUnhooked + ")"}},
		"inconclusive": {verdicts{probe: probeReport{outcome: probeInconclusive}}, []string{"; id-less tools/call answered by someone (" + verdictInconclusive + ")"}},
	}
	for name, tc := range cases {
		wantContains(t, name+" summary", tc.v.summary(), tc.want...)
	}
	// The failure sentence names every verdict the check found.
	f := &verifyFailure{leaks: 1, configEdited: true, configExpected: strings.Repeat("0", 64), liveDiffs: 2, probe: probeInconclusive, server: "s1", url: "http://127.0.0.1:1/s1/mcp?q=" + plant("query")}
	wantContains(t, "failure", f.Error(), "1 tool(s) leak", "recorded with --expect-body-hash", "2 place(s)", verdictInconclusive, "treat the gateway as unhooked")
	wantNotContains(t, "failure", f.Error(), canary, "q=")
	wantContains(t, "unhooked failure", (&verifyFailure{probe: probeUnhooked}).Error(), verdictUnhooked, "L17")
	wantContains(t, "unreadable failure", (&verifyFailure{configEdited: true, configReason: "x"}).Error(), "could not be read")
	wantContains(t, "edited failure", (&verifyFailure{configEdited: true}).Error(), "edited after emit wrote it")
}
