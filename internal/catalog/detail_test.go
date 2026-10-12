package catalog

import (
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The detail format Integrity reads is fixed by the writer: four fields first,
// values without spaces, a note after. The reader must not be fooled by a
// quoted class in the note or by a detail of another shape, and it reads the
// after half of the state and proposals transitions (D13).
func TestToolDetail_FieldsRoundTrip(t *testing.T) {
	before := toolState{tool: lifecycle.Tool{State: lifecycle.Enabled, LastSeen: strings.Repeat("a", 64)}, budget: 3}
	after := toolState{tool: lifecycle.Tool{State: lifecycle.ChangedPendingReapproval, LastSeen: lifecycle.UnusableDigest}, budget: 4}
	detail := toolDetail("", before, after, ` reason="http status 401" budget=20`)
	if want := `digest=- state=enabled->changed_pending_reapproval last_seen=unusable proposals=3->4 reason="http status 401" budget=20`; detail != want {
		t.Fatalf("toolDetail = %q, want %q", detail, want)
	}
	for key, want := range map[string]string{fieldDigest: "-", fieldLastSeen: "unusable", fieldState: "enabled->changed_pending_reapproval", fieldProposals: "3->4", "budget": "20"} {
		if got, ok := detailField(detail, key); !ok || got != want {
			t.Errorf("detailField(%s) = %q, %t; want %q", key, got, ok, want)
		}
	}
	if _, ok := detailField(detail, "reason=http"); ok {
		t.Error("a quoted class must not read as a field")
	}
	trace, missing := parseToolTrace(audit.Entry{Seq: 9, AfterHash: "h", Detail: detail})
	if missing != "" || trace.state != string(lifecycle.ChangedPendingReapproval) || trace.lastSeen != lifecycle.UnusableDigest || trace.budget != 4 || trace.approved != "h" {
		t.Errorf("parseToolTrace = %+v, %q", trace, missing)
	}
	for detail, field := range map[string]string{
		"digest=- state=enabled->enabled proposals=0->0":              fieldLastSeen,
		"digest=- last_seen=- proposals=0->0":                         fieldState,
		"digest=- state=enabled last_seen=- proposals=0->0":           fieldState,
		"digest=- state=enabled->enabled last_seen=-":                 fieldProposals,
		"digest=- state=enabled->enabled last_seen=- proposals=0->x":  fieldProposals,
		"digest=- state=enabled->enabled last_seen=- proposals=0->-1": fieldProposals,
	} {
		if _, got := parseToolTrace(audit.Entry{Detail: detail}); got != field {
			t.Errorf("parseToolTrace(%q) reports %q missing, want %q", detail, got, field)
		}
	}
	absent := toolDetail(strings.Repeat("b", 64), before, toolState{tool: lifecycle.Tool{State: lifecycle.Deprecated}}, "")
	if v, _ := detailField(absent, fieldLastSeen); v != noDigest || fromNoDigest(v) != "" {
		t.Errorf("an absent tool must record last_seen=%s, got %q", noDigest, v)
	}
	for _, other := range []string{"crawl=1 tools=2 changes=0 rejected=0", "allow_private=true url_sha256=ab", "paused=true", "crawl=3 reason=invalid-name name=<unprintable>"} {
		if isToolDetail(other) {
			t.Errorf("%q is not a tool detail", other)
		}
	}
	spec := ServerSpec{Name: "alpha", URL: "https://alpha.example.com/mcp?token=SECRET", AllowPrivate: true}
	if got, want := serverAddedDetail(spec), "allow_private=true url_sha256="+urlSHA256(spec.URL); got != want || strings.Contains(got, "SECRET") || len(urlSHA256(spec.URL)) != 64 {
		t.Errorf("serverAddedDetail = %q, want %q and no URL text", got, want)
	}
	for detail, want := range map[string]struct{ value, ok bool }{"paused=true": {true, true}, "paused=false": {false, true}, "paused=1": {false, false}, "x=true": {false, false}} {
		if value, ok := detailBool(detail, fieldPaused); value != want.value || ok != want.ok {
			t.Errorf("detailBool(%q) = %t, %t; want %+v", detail, value, ok, want)
		}
	}
	// The decision names and guard statements the reader relies on.
	for decision, event := range map[string]string{decisionApprove: "version.approved", decisionReject: "version.rejected", decisionRollback: "version.rolled_back", "bless": ""} {
		if got := decisionEvent(decision); got != event || (event != "" && !isDecisionEvent(got)) {
			t.Errorf("decisionEvent(%s) = %q, want %q", decision, got, event)
		}
	}
	if kind, name := parseGuardDDL("CREATE"); kind != "" || name != "" {
		t.Errorf("parseGuardDDL of a fragment = %q %q", kind, name)
	}
	if kind, name := parseGuardDDL("CREATE UNIQUE INDEX idx ON t (c)"); kind != "index" || name != "idx" {
		t.Errorf("parseGuardDDL(unique index) = %q %q", kind, name)
	}
	if !slices.Equal(guardTriggers(), []string{
		"audit_log_no_update", "audit_log_no_delete", "audit_log_sequential",
		"tool_versions_no_delete", "tool_versions_immutable", "tool_versions_no_replace", "tool_versions_positive_id",
		"proposers_no_update", "proposers_no_delete", "proposers_append_only",
		"approvals_no_update", "approvals_no_delete", "approvals_no_replace", "approvals_positive_id", "tools_no_delete",
	}) || !slices.Equal(guardIndexes(), []string{"one_pending_version", "one_approved_version", "approvals_by_version", "audit_log_by_subject"}) {
		t.Errorf("guard names parsed from the DDL = %v, %v", guardTriggers(), guardIndexes())
	}
}
