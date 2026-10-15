package signing

import (
	"crypto/elliptic"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// MarshalTrustList writes the canonical document the plan gives, with the
// signers as {"key","name"} objects in the order given, and ParseTrustList
// reads it back field for field, for Ed25519 and ECDSA keys.
func TestTrustList_MarshalAndParseRoundTrip(t *testing.T) {
	t.Parallel()
	a, b := sigtest.GenerateEd25519(t), sigtest.GenerateECDSA(t, elliptic.P256())
	l := sampleTrustList(a, b)
	bytes := mustMarshalTrustList(t, l)
	want := `{"catalog":"` + sampleCatalog + `","prev_head":"` + samplePrevHead + `","signed_at":"2026-10-15T12:30:45Z","signer":"` +
		Fingerprint(a.Public) + `","signers":[{"key":"` + MarshalKey(a.Public) + `","name":"alice"},{"key":"` + MarshalKey(b.Public) +
		`","name":"bob"}],"threshold":1,"type":"toolwarrant/trust-list/v1","version":1}`
	if string(bytes) != want {
		t.Fatalf("MarshalTrustList =\n%s\nwant\n%s", bytes, want)
	}
	got, err := ParseTrustList(bytes)
	if err != nil || !reflect.DeepEqual(got, l) {
		t.Fatalf("ParseTrustList = %+v, %v; want %+v", got, err, l)
	}
	if !strings.HasPrefix(MarshalKey(a.Public), "ssh-ed25519 AAAA") || strings.Contains(MarshalKey(a.Public), "\n") {
		t.Errorf("MarshalKey = %q", MarshalKey(a.Public))
	}
	for _, k := range []sigtest.Key{a, b} {
		pub, err := ParseAuthorizedKey(MarshalKey(k.Public))
		if err != nil || Fingerprint(pub) != Fingerprint(k.Public) {
			t.Errorf("ParseAuthorizedKey(MarshalKey) = %v, %v", pub, err)
		}
	}
}

// A stored key line has one spelling: a comment, options, a second space,
// surrounding space, a tab, a newline, a type that does not match the blob,
// non-strict base64, a blob with trailing bytes and a line over the bound are
// each refused, by ParseAuthorizedKey directly and by ParseTrustList through a
// list that carries them.
func TestTrustList_RefusesKeyCommentsOptionsAndNonCanonicalKeyLines(t *testing.T) {
	t.Parallel()
	a, b := sigtest.GenerateEd25519(t), sigtest.GenerateECDSA(t, elliptic.P256())
	// An ECDSA P-256 blob is 104 bytes, two over a multiple of three, so its
	// base64 ends in one '=' and the character before it has two unused bits;
	// an Ed25519 blob is 51 bytes and has neither, which is why b is the key
	// the loose spellings are made from.
	line := MarshalKey(b.Public)
	typ, b64, _ := strings.Cut(line, " ")
	loose := looseBase64(t, b64)
	cases := map[string]string{
		"comment":          line + " alice@example",
		"options":          "namespaces=\"decision@toolwarrant.invalid\" " + line,
		"two spaces":       typ + "  " + b64,
		"trailing space":   line + " ",
		"leading space":    " " + line,
		"tab":              typ + "\t" + b64,
		"newline":          line + "\n",
		"type mismatch":    "ssh-rsa " + b64,
		"other type word":  "ssh-ed25519-cert-v01@openssh.com " + b64,
		"loose base64":     typ + " " + loose,
		"no padding check": typ + " " + strings.TrimRight(b64, "="),
		"empty base64":     typ + " ",
		"empty type":       " " + b64,
		"empty":            "",
		"over the bound":   typ + " " + strings.Repeat("A", MaxKeyLineBytes),
		"not base64":       typ + " not*base64",
	}
	for label, in := range cases {
		if _, err := ParseAuthorizedKey(in); !errors.Is(err, ErrKeyLine) {
			t.Errorf("ParseAuthorizedKey(%s): error %v, want ErrKeyLine", label, err)
		}
		l := sampleTrustList(a, b)
		l.Signers[1] = Signer{Key: in, Name: "bob"}
		if _, err := MarshalTrustList(l); !errors.Is(err, ErrPayload) {
			t.Errorf("MarshalTrustList with %s: error %v, want ErrPayload", label, err)
		}
	}
	if loose == b64 {
		t.Fatal("the loose base64 case is the canonical line; the test proves nothing")
	}
	if _, err := ParseAuthorizedKey(line); err != nil {
		t.Errorf("the canonical line: %v", err)
	}
}

// The shape bounds of a list: one to MaxSigners operators, a threshold between
// one and the number of signers, a version from one, canonical integers, each
// signer an object of exactly key and name with a D7 name, signers an array.
func TestTrustList_RefusesBoundsAndShape(t *testing.T) {
	t.Parallel()
	keys := make([]sigtest.Key, MaxSigners+1)
	for i := range keys {
		keys[i] = sigtest.GenerateEd25519(t)
	}
	tooMany := sampleTrustList(keys...)
	for i := range tooMany.Signers {
		tooMany.Signers[i].Name = "op" + strings.Repeat("x", i/26) + string(rune('a'+i%26))
	}
	if _, err := MarshalTrustList(tooMany); !errors.Is(err, ErrPayload) {
		t.Errorf("%d signers marshalled: %v", len(keys), err)
	}
	full := tooMany
	full.Signers = full.Signers[:MaxSigners]
	fb := mustMarshalTrustList(t, full)
	if got, err := ParseTrustList(fb); err != nil || len(got.Signers) != MaxSigners {
		t.Errorf("%d signers: %v", MaxSigners, err)
	}
	a := keys[0]
	l := sampleTrustList(a, keys[1])
	b := string(mustMarshalTrustList(t, l))
	structural := map[string]TrustList{
		"no signers":          {Catalog: l.Catalog, PrevHead: l.PrevHead, SignedAt: l.SignedAt, Signer: l.Signer, Threshold: 1, Version: 1},
		"threshold 0":         withThreshold(l, 0),
		"threshold > signers": withThreshold(l, 3),
		"version 0":           withVersion(l, 0),
		"version over bound":  withVersion(l, maxTrustVersion+1),
		"name upper-case":     withName(l, 1, "Bob"),
		"name empty":          withName(l, 1, ""),
		"name over cap":       withName(l, 1, strings.Repeat("b", maxActorNameLen+1)),
		"bad catalog":         {Catalog: "xyz", PrevHead: l.PrevHead, SignedAt: l.SignedAt, Signer: l.Signer, Signers: l.Signers, Threshold: 1, Version: 1},
		"bad signer":          {Catalog: l.Catalog, PrevHead: l.PrevHead, SignedAt: l.SignedAt, Signer: "SHA256:", Signers: l.Signers, Threshold: 1, Version: 1},
	}
	for label, bad := range structural {
		if _, err := MarshalTrustList(bad); !errors.Is(err, ErrPayload) {
			t.Errorf("marshal %s: error %v, want ErrPayload", label, err)
		}
	}
	textual := map[string]string{
		"version 01":           strings.Replace(b, `"version":1`, `"version":01`, 1),
		"version 1.0":          strings.Replace(b, `"version":1`, `"version":1.0`, 1),
		"version 1e0":          strings.Replace(b, `"version":1`, `"version":1e0`, 1),
		"version string":       strings.Replace(b, `"version":1`, `"version":"1"`, 1),
		"version negative":     strings.Replace(b, `"version":1`, `"version":-1`, 1),
		"threshold 2 of 2":     strings.Replace(b, `"threshold":1`, `"threshold":2`, 1),
		"threshold 3 of 2":     strings.Replace(b, `"threshold":1`, `"threshold":3`, 1),
		"signers object":       strings.Replace(b, `"signers":[`, `"signers":{"a":[`, 1) + "}",
		"signers null":         strings.Replace(b[:strings.Index(b, `"signers":`)]+`"signers":null,"threshold":1,"type":"toolwarrant/trust-list/v1","version":1}`, "", "", 1),
		"signer extra key":     strings.Replace(b, `"name":"bob"}`, `"name":"bob","role":"x"}`, 1),
		"signer missing name":  strings.Replace(b, `,"name":"bob"}`, `}`, 1),
		"signer duplicate key": strings.Replace(b, `"name":"bob"}`, `"name":"bob","name":"bob"}`, 1),
		"signer name number":   strings.Replace(b, `"name":"bob"}`, `"name":1}`, 1),
		"signer not object":    strings.Replace(b, `{"key":"`+MarshalKey(keys[1].Public)+`","name":"bob"}`, `"bob"`, 1),
		"unknown top key":      strings.Replace(b, `"version":1}`, `"version":1,"x":1}`, 1),
		"trailing byte":        b + " ",
	}
	for label, in := range textual {
		if label == "threshold 2 of 2" {
			// Two of two is a shape the parser allows; internal/trust pins
			// threshold 1 (O-14). It must still parse.
			if _, err := ParseTrustList([]byte(in)); err != nil {
				t.Errorf("%s: %v, want a parse (the threshold rule is internal/trust's)", label, err)
			}
			continue
		}
		if _, err := ParseTrustList([]byte(in)); !errors.Is(err, ErrPayload) {
			t.Errorf("parse %s: error %v, want ErrPayload", label, err)
		}
	}
}

// looseBase64 sets the lowest unused bit of the last data character of a
// padded standard-base64 string, which a strict decoder refuses and a loose
// one reads as the same bytes.
func looseBase64(t testing.TB, b64 string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.LastIndexFunc(b64, func(r rune) bool { return r != '=' })
	if last < 0 || !strings.HasSuffix(b64, "=") {
		t.Fatal("the key line has no padding, so it has no unused bits")
	}
	v := strings.IndexByte(alphabet, b64[last]) | 0x01
	return b64[:last] + string(alphabet[v]) + b64[last+1:]
}

func withThreshold(l TrustList, n int) TrustList { l.Threshold = n; return l }

func withVersion(l TrustList, n int) TrustList { l.Version = n; return l }

func withName(l TrustList, i int, name string) TrustList {
	signers := make([]Signer, len(l.Signers))
	copy(signers, l.Signers)
	signers[i].Name = name
	l.Signers = signers
	return l
}
