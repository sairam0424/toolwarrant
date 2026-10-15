package trust

import (
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// FuzzRecordValidate holds Validate to its laws over arbitrary bytes read
// through signing.ParseTrustList: never panic; whatever it accepts has one to
// signing.MaxSigners operators, each name canonical and unique, each
// fingerprint unique and looked up to its own name, threshold one; the
// allowed_signers rendering has one line per operator carrying the stored key
// line; and a second Validate of the same list gives the same Record. Run it
// by hand with
// go test -run '^$' -fuzz FuzzRecordValidate -fuzztime 20s ./internal/trust/.
func FuzzRecordValidate(f *testing.F) {
	a, b := sigtest.GenerateEd25519(f), sigtest.GenerateEd25519(f)
	good, err := signing.MarshalTrustList(listOf(1, named{"alice", a}, named{"bob", b}))
	if err != nil {
		f.Fatal(err)
	}
	g := string(good)
	seeds := []string{
		g,
		strings.Replace(g, `"name":"bob"`, `"name":"alice"`, 1),
		strings.Replace(g, signing.MarshalKey(b.Public), signing.MarshalKey(a.Public), 1),
		strings.Replace(g, `"threshold":1`, `"threshold":2`, 1),
		strings.Replace(g, `"version":1`, `"version":2`, 1),
		strings.Replace(g, `"signers":[`, `"signers":[{"key":"ssh-ed25519 AAAA","name":"x"},`, 1),
		`{}`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		l, err := signing.ParseTrustList(in)
		if err != nil {
			return
		}
		r, err := Validate(l)
		if err != nil {
			return
		}
		checkAcceptedRecord(t, l, r)
	})
}

// checkAcceptedRecord asserts the laws of a Record Validate accepted.
func checkAcceptedRecord(t *testing.T, l signing.TrustList, r Record) {
	t.Helper()
	if r.Threshold != Threshold || r.Version != l.Version || len(r.Signers) != len(l.Signers) || len(r.Signers) == 0 || len(r.Signers) > signing.MaxSigners {
		t.Fatalf("accepted %+v from %+v", r, l)
	}
	names, fps := map[string]bool{}, map[string]bool{}
	for i, op := range r.Signers {
		if n, err := NormalizeName(op.Name); err != nil || n != op.Name || names[op.Name] {
			t.Fatalf("signers[%d].name %q: canonical %q, %v, seen %t", i, op.Name, n, err, names[op.Name])
		}
		if fps[op.Fingerprint] || op.Key != l.Signers[i].Key {
			t.Fatalf("signers[%d]: fingerprint seen %t, key kept %t", i, fps[op.Fingerprint], op.Key == l.Signers[i].Key)
		}
		names[op.Name], fps[op.Fingerprint] = true, true
		if name, ok := r.Lookup(op.Fingerprint); !ok || name != op.Name {
			t.Fatalf("Lookup(signers[%d]) = %q, %t", i, name, ok)
		}
		if err := r.Authorize(op.Fingerprint, op.Name); err != nil {
			t.Fatalf("Authorize(signers[%d]): %v", i, err)
		}
	}
	file, err := AllowedSigners(r)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(file), "\n"), "\n")
	if len(lines) != len(r.Signers) {
		t.Fatalf("%d lines for %d signers", len(lines), len(r.Signers))
	}
	for i, line := range lines {
		want := r.Signers[i].Name + " " + allowedSignersOption + " " + r.Signers[i].Key
		if line != want {
			t.Fatalf("line %d = %q, want %q", i, line, want)
		}
	}
	again, err := Validate(l)
	if err != nil || !equalRecords(again, r) {
		t.Fatalf("a second Validate = %+v, %v", again, err)
	}
}

// equalRecords compares two records field by field.
func equalRecords(x, y Record) bool {
	if x.Version != y.Version || x.Threshold != y.Threshold || x.valid != y.valid || len(x.Signers) != len(y.Signers) {
		return false
	}
	for i := range x.Signers {
		if x.Signers[i] != y.Signers[i] {
			return false
		}
	}
	return true
}
