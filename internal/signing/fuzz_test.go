package signing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The fuzzers hold the parsers to two laws over arbitrary input: never panic,
// and whatever parses re-marshals to exactly the input (so no two inputs
// parse to one decision or list, and nothing parses that Marshal would not
// write). Run them by hand with
// go test -run '^$' -fuzz FuzzParseDecision -fuzztime 20s ./internal/signing/.

func FuzzParseDecision(f *testing.F) {
	fp := Fingerprint(sigtest.GenerateEd25519(f).Public)
	good := string(mustMarshalDecision(f, sampleDecision(fp)))
	seeds := []string{
		good,
		strings.Replace(good, `"kind":"approve"`, `"kind":"pause"`, 1),
		strings.Replace(good, TypeDecision, TypeTrustList, 1),
		strings.Replace(good, `"tool":"echo"`, `"tool":1`, 1),
		good + " ",
		`{}`,
		`[]`,
		``,
		"\xff",
		`{"type":"toolwarrant/decision/v1"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseDecision(b)
		if err != nil {
			return
		}
		again, err := MarshalDecision(d)
		if err != nil {
			t.Fatalf("parsed but does not marshal: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("parsed %q, re-marshalled %q", b, again)
		}
	})
}

func FuzzParseTrustList(f *testing.F) {
	k := sigtest.GenerateEd25519(f)
	good := string(mustMarshalTrustList(f, sampleTrustList(k)))
	seeds := []string{
		good,
		strings.Replace(good, `"version":1`, `"version":2`, 1),
		strings.Replace(good, `"threshold":1`, `"threshold":0`, 1),
		strings.Replace(good, TypeTrustList, TypeDecision, 1),
		strings.Replace(good, `"signers":[`, `"signers":{`, 1),
		good + "\n",
		`{}`,
		``,
		`{"type":"toolwarrant/trust-list/v1","signers":[]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseTrustList(b)
		if err != nil {
			return
		}
		again, err := MarshalTrustList(l)
		if err != nil {
			t.Fatalf("parsed but does not marshal: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("parsed %q, re-marshalled %q", b, again)
		}
	})
}

func FuzzUnarmor(f *testing.F) {
	k := sigtest.GenerateEd25519(f)
	r := mustSign(f, mustMarshalDecision(f, sampleDecision(Fingerprint(k.Public))), k, NamespaceDecision)
	armored, err := Armor(r.Signature)
	if err != nil {
		f.Fatal(err)
	}
	seeds := [][]byte{
		armored,
		bytes.ReplaceAll(armored, []byte("SSH SIGNATURE"), []byte("PUBLIC KEY")),
		append(bytes.Clone(armored), armored...),
		[]byte("-----BEGIN SSH SIGNATURE-----\n\n-----END SSH SIGNATURE-----\n"),
		[]byte(""),
		[]byte("-----BEGIN"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		blob, err := Unarmor(b)
		if err != nil {
			return
		}
		if len(blob) == 0 || len(blob) > MaxSignatureBytes {
			t.Fatalf("Unarmor returned %d bytes", len(blob))
		}
		again, err := Armor(blob)
		if err != nil {
			t.Fatalf("unarmored but does not armor: %v", err)
		}
		back, err := Unarmor(again)
		if err != nil || !bytes.Equal(back, blob) {
			t.Fatalf("Armor/Unarmor round trip changed the blob: %v", err)
		}
	})
}
