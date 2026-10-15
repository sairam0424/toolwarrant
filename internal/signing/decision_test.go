package signing

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The sample approval has one byte form: the RFC 8785 document the plan
// writes, which MarshalDecision produces and ParseDecision reads back.
func sampleDecisionJSON(fp string) string {
	return `{"actor":"alice","catalog":"` + sampleCatalog + `","digest":"` + sampleDigest +
		`","kind":"approve","prev_head":"` + samplePrevHead + `","server":"mock","signed_at":"2026-10-15T12:30:45Z","signer":"` +
		fp + `","tool":"echo","type":"toolwarrant/decision/v1"}`
}

// MarshalDecision writes the exact canonical form; ParseDecision accepts
// exactly those bytes and refuses whitespace, another key order, a trailing
// byte, an unknown or missing key, a wrong type, an unknown kind, a duplicate
// key, a non-string value, invalid UTF-8, a field over its cap and a digest or
// tool the kind does not name.
func TestDecision_MarshalIsCanonicalAndParseRequiresTheExactBytes(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	fp := Fingerprint(k.Public)
	d := sampleDecision(fp)
	b := mustMarshalDecision(t, d)
	if string(b) != sampleDecisionJSON(fp) {
		t.Fatalf("MarshalDecision =\n%s\nwant\n%s", b, sampleDecisionJSON(fp))
	}
	canon, err := gate.Canonical(b)
	if err != nil || !bytes.Equal(canon, b) {
		t.Fatalf("the marshalled bytes are not their own canonical form: %v", err)
	}
	got, err := ParseDecision(b)
	if err != nil || got != d {
		t.Fatalf("ParseDecision = %+v, %v; want %+v", got, err, d)
	}
	refused := map[string]struct {
		in   string
		want error
	}{
		"whitespace":          {strings.Replace(string(b), `","kind"`, `", "kind"`, 1), ErrPayload},
		"key order":           {`{"type":"toolwarrant/decision/v1",` + strings.TrimPrefix(strings.TrimSuffix(string(b), `,"type":"toolwarrant/decision/v1"}`), "{") + "}", ErrPayload},
		"trailing byte":       {string(b) + "\n", ErrPayload},
		"trailing object":     {string(b) + "{}", ErrPayload},
		"unknown key":         {strings.Replace(string(b), `"tool":`, `"note":"x","tool":`, 1), ErrPayload},
		"missing key":         {strings.Replace(string(b), `"tool":"echo",`, "", 1), ErrPayload},
		"duplicate key":       {strings.Replace(string(b), `"tool":"echo",`, `"tool":"echo","tool":"echo",`, 1), ErrPayload},
		"non-string value":    {strings.Replace(string(b), `"tool":"echo"`, `"tool":1`, 1), ErrPayload},
		"wrong type":          {strings.Replace(string(b), TypeDecision, TypeTrustList, 1), ErrType},
		"unknown kind":        {strings.Replace(string(b), `"kind":"approve"`, `"kind":"bless"`, 1), ErrPayload},
		"upper-case digest":   {strings.Replace(string(b), sampleDigest, strings.ToUpper(sampleDigest), 1), ErrPayload},
		"short head":          {strings.Replace(string(b), samplePrevHead, samplePrevHead[1:], 1), ErrPayload},
		"actor over cap":      {strings.Replace(string(b), `"actor":"alice"`, `"actor":"`+strings.Repeat("a", maxActorNameLen+1)+`"`, 1), ErrPayload},
		"actor upper-case":    {strings.Replace(string(b), `"actor":"alice"`, `"actor":"Alice"`, 1), ErrPayload},
		"server with slash":   {strings.Replace(string(b), `"server":"mock"`, `"server":"mock/x"`, 1), ErrPayload},
		"tool over cap":       {strings.Replace(string(b), `"tool":"echo"`, `"tool":"`+strings.Repeat("t", 257)+`"`, 1), ErrPayload},
		"signer not a print":  {strings.Replace(string(b), fp, "SHA256:short", 1), ErrPayload},
		"signed_at offset":    {strings.Replace(string(b), "2026-10-15T12:30:45Z", "2026-10-15T12:30:45+00:00", 1), ErrPayload},
		"signed_at fraction":  {strings.Replace(string(b), "2026-10-15T12:30:45Z", "2026-10-15T12:30:45.000Z", 1), ErrPayload},
		"pause with a tool":   {strings.Replace(strings.Replace(string(b), `"kind":"approve"`, `"kind":"pause"`, 1), `"digest":"`+sampleDigest+`"`, `"digest":""`, 1), ErrPayload},
		"disable with digest": {strings.Replace(string(b), `"kind":"approve"`, `"kind":"disable"`, 1), ErrPayload},
		"approve no digest":   {strings.Replace(string(b), `"digest":"`+sampleDigest+`"`, `"digest":""`, 1), ErrPayload},
		"invalid utf-8":       {strings.Replace(string(b), `"tool":"echo"`, "\"tool\":\"e\xffo\"", 1), ErrPayload},
		"empty":               {"", ErrPayload},
		"array":               {"[" + string(b) + "]", ErrPayload},
		"oversized":           {string(b) + strings.Repeat(" ", MaxPayloadBytes), ErrPayload},
	}
	for label, c := range refused {
		_, err := ParseDecision([]byte(c.in))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: error %v, want %v", label, err, c.want)
		}
	}
}

// Every kind has one shape: pause and resume name a server only, disable,
// enable and budget_reset name a tool, approve, reject and rollback name a
// tool and a digest. Each marshals and parses back.
func TestDecision_EveryKindMarshalsItsOwnShape(t *testing.T) {
	t.Parallel()
	fp := Fingerprint(sigtest.GenerateEd25519(t).Public)
	for _, kind := range []Kind{KindApprove, KindReject, KindRollback, KindDisable, KindEnable, KindPause, KindResume, KindBudgetReset} {
		d := sampleDecision(fp)
		d.Kind = kind
		if !kind.NamesVersion() {
			d.Digest = ""
		}
		if !kind.NamesTool() {
			d.Tool = ""
		}
		b, err := MarshalDecision(d)
		if err != nil {
			t.Errorf("%s: %v", kind, err)
			continue
		}
		got, err := ParseDecision(b)
		if err != nil || got != d {
			t.Errorf("%s: parse back %+v, %v", kind, got, err)
		}
	}
	if Kind("bless").Valid() || Kind("").Valid() || Kind("Approve").Valid() {
		t.Error("a kind outside the eight is valid")
	}
	if !KindApprove.NamesVersion() || !KindReject.NamesVersion() || !KindRollback.NamesVersion() || KindDisable.NamesVersion() || KindPause.NamesVersion() {
		t.Error("NamesVersion is wrong for a kind")
	}
	if KindPause.NamesTool() || KindResume.NamesTool() || !KindBudgetReset.NamesTool() || !KindEnable.NamesTool() || Kind("bless").NamesTool() {
		t.Error("NamesTool is wrong for a kind")
	}
	if _, err := MarshalDecision(Decision{}); !errors.Is(err, ErrPayload) {
		t.Errorf("an empty decision marshalled: %v", err)
	}
	unset := sampleDecision(fp)
	unset.SignedAt = time.Time{}
	if _, err := MarshalDecision(unset); !errors.Is(err, ErrPayload) || !strings.Contains(err.Error(), "signed_at is unset") {
		t.Errorf("a decision without signed_at marshalled: %v", err)
	}
	sub := sampleDecision(fp)
	sub.SignedAt = sub.SignedAt.Add(700 * time.Millisecond).In(time.FixedZone("x", 3600))
	b, err := MarshalDecision(sub)
	if err != nil || !strings.Contains(string(b), `"signed_at":"2026-10-15T12:30:45Z"`) {
		t.Errorf("signed_at is not written in UTC to the second: %s, %v", b, err)
	}
}

// A trust list signed under the decision namespace verifies as bytes, and
// ParseDecision then refuses it by its type; the reverse holds for a decision
// handed to ParseTrustList. The type inside the signed bytes, not the parser
// a caller happens to use, decides what a payload is (finding 8).
func TestDecision_RefusesATrustListUnderTheDecisionNamespace(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	list := mustMarshalTrustList(t, sampleTrustList(k))
	r := mustSign(t, list, k, NamespaceDecision)
	if _, err := Verify(r.Payload, r.Signature, NamespaceDecision, r.Signer); err != nil {
		t.Fatalf("the bytes do not verify under the namespace they were signed under: %v", err)
	}
	_, err := ParseDecision(r.Payload)
	wantErrIs(t, "trust list as a decision", err, ErrType, `"toolwarrant/trust-list/v1", want toolwarrant/decision/v1`)
	decision := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
	_, err = ParseTrustList(decision)
	wantErrIs(t, "decision as a trust list", err, ErrType, `"toolwarrant/decision/v1", want toolwarrant/trust-list/v1`)
	_, err = Verify(r.Payload, r.Signature, NamespaceTrust, r.Signer)
	wantErrIs(t, "the list's signature under the trust namespace", err, ErrNamespaceMismatch, "")
}
