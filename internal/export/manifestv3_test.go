package export

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D21 (e): the manifest names the catalog state it mirrors. Version 3 carries
// the head of the audit chain the catalog had verified when the approvals
// were read and the digest profile every digest was computed under; the two
// fields sit between the status and the tool list, so a reader sees them
// before the first entry.
func TestWrite_ManifestRecordsTheAuditHeadAndProfile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "a", "1"), mkTool(t, "s", "b", "2"))
	doc := readManifest(t, dir)
	if doc.Version != 3 || doc.AuditHead != testHead || doc.DigestProfile != testProfile {
		t.Fatalf("manifest = version %d, head %q, profile %q; want 3, %s, %s", doc.Version, doc.AuditHead, doc.DigestProfile, testHead, testProfile)
	}
	raw := readFile(t, filepath.Join(dir, manifestName))
	status, head, profile, tools := strings.Index(raw, `"status"`), strings.Index(raw, `"audit_head": "`+testHead+`"`), strings.Index(raw, `"digest_profile": "`+testProfile+`"`), strings.Index(raw, `"tools"`)
	if status <= 0 || head <= status || profile <= head || tools <= profile {
		t.Fatalf("the catalog fields are not between the status and the tools:\n%s", raw)
	}

	// A moved head rewrites the manifest alone: the tool files keep their
	// bytes and their times, and the report counts them unchanged.
	before := snapshot(t, dir)
	rep := mustWriteWith(t, dir, headOpts(otherHead), mkTool(t, "s", "a", "1"), mkTool(t, "s", "b", "2"))
	wantReport(t, rep, 0, 0, 2)
	after := snapshot(t, dir)
	for p, e := range before {
		if p == manifestName || p == "." {
			continue // the directory's own time moves with the rename into it
		}
		if after[p] != e {
			t.Errorf("%s changed with the head: %+v -> %+v", p, e, after[p])
		}
	}
	if doc := readManifest(t, dir); doc.AuditHead != otherHead {
		t.Fatalf("manifest head = %q after the move, want %s", doc.AuditHead, otherHead)
	}
	if after[manifestName] == before[manifestName] {
		t.Fatal("the manifest did not change although the head moved")
	}
}

// Options the manifest cannot carry, or the signer cannot use, are refused
// before anything is planned or written: the directory is not even created.
func TestWrite_RefusesOptionsTheManifestCannotCarry(t *testing.T) {
	cases := map[string]Options{
		"empty head":        {AuditHead: "", DigestProfile: testProfile},
		"short head":        {AuditHead: testHead[:63], DigestProfile: testProfile},
		"upper-case head":   {AuditHead: strings.ToUpper(testHead), DigestProfile: testProfile},
		"non-hex head":      {AuditHead: strings.Repeat("g", 64), DigestProfile: testProfile},
		"empty profile":     {AuditHead: testHead, DigestProfile: ""},
		"profile with dot":  {AuditHead: testHead, DigestProfile: "full.v1"},
		"profile too long":  {AuditHead: testHead, DigestProfile: strings.Repeat("a", maxProfileBytes+1)},
		"short signing key": {AuditHead: testHead, DigestProfile: testProfile, SignKey: ed25519.PrivateKey(make([]byte, 32))},
	}
	for label, opts := range cases {
		dir := filepath.Join(t.TempDir(), "out")
		if _, err := Write(dir, []Tool{mkTool(t, "s", "a", "1")}, opts); err == nil {
			t.Errorf("%s: want an error", label)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s: a refused option must not create the directory", label)
		}
	}
}

// parseManifest reads version 3 and version 2 (from before the catalog
// fields), each only in its own shape, and nothing else.
func TestParseManifest_ReadsVersionTwoAndThreeInTheirOwnShapes(t *testing.T) {
	v3 := `{"version":3,"status":"complete","audit_head":"` + testHead + `","digest_profile":"full-v1","tools":[]}`
	v2 := `{"version":2,"status":"complete","tools":[]}`
	for label, raw := range map[string]string{"version 3": v3, "version 2": v2} {
		doc, ok := parseManifest([]byte(raw))
		if !ok {
			t.Errorf("%s: own shape refused", label)
		}
		if label == "version 2" && (doc.AuditHead != "" || doc.DigestProfile != "") {
			t.Errorf("version 2 read with catalog fields: %+v", doc)
		}
		if label == "version 3" && (doc.AuditHead != testHead || doc.DigestProfile != "full-v1") {
			t.Errorf("version 3 read without its fields: %+v", doc)
		}
	}
	bad := map[string]string{
		"version 3 without a head":       `{"version":3,"status":"complete","digest_profile":"full-v1","tools":[]}`,
		"version 3 without a profile":    `{"version":3,"status":"complete","audit_head":"` + testHead + `","tools":[]}`,
		"version 3 upper-case head":      `{"version":3,"status":"complete","audit_head":"` + strings.ToUpper(testHead) + `","digest_profile":"full-v1","tools":[]}`,
		"version 3 short head":           `{"version":3,"status":"complete","audit_head":"abc","digest_profile":"full-v1","tools":[]}`,
		"version 3 profile with a space": `{"version":3,"status":"complete","audit_head":"` + testHead + `","digest_profile":"full v1","tools":[]}`,
		"version 2 with a head":          `{"version":2,"status":"complete","audit_head":"` + testHead + `","tools":[]}`,
		"version 2 with a profile":       `{"version":2,"status":"complete","digest_profile":"full-v1","tools":[]}`,
		"version 4":                      `{"version":4,"status":"complete","audit_head":"` + testHead + `","digest_profile":"full-v1","tools":[]}`,
	}
	for label, raw := range bad {
		if doc, ok := parseManifest([]byte(raw)); ok {
			t.Errorf("%s: accepted %+v", label, doc)
		}
	}
}

// An export written by the previous release left a version 2 manifest. The
// next Write still reads it as the record of the files it created, so the
// stale file is removed and the manifest comes out as version 3.
func TestWrite_CleansUpAfterAVersionTwoManifest(t *testing.T) {
	dir := t.TempDir()
	old := mkTool(t, "s", "old", "1")
	mustWrite(t, dir, old)
	raw := readFile(t, filepath.Join(dir, manifestName))
	v2 := strings.Replace(raw, `"version": 3,`, `"version": 2,`, 1)
	v2 = strings.Replace(v2, `  "audit_head": "`+testHead+`",`+"\n", "", 1)
	v2 = strings.Replace(v2, `  "digest_profile": "`+testProfile+`",`+"\n", "", 1)
	if doc, ok := parseManifest([]byte(v2)); !ok || doc.Version != 2 {
		t.Fatalf("the rewritten manifest is not a version 2 one:\n%s", v2)
	}
	writeFile(t, filepath.Join(dir, manifestName), v2)

	rep := mustWrite(t, dir, mkTool(t, "s", "new", "2"))
	wantReport(t, rep, 1, 1, 0)
	if _, err := os.Stat(filepath.Join(dir, "s", "old.json")); !os.IsNotExist(err) {
		t.Errorf("old.json listed by the version 2 manifest was not removed: %v", err)
	}
	if doc := readManifest(t, dir); doc.Version != 3 || doc.AuditHead != testHead {
		t.Fatalf("manifest after the upgrade = %+v", doc)
	}
}
