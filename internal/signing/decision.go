package signing

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/toolname"
)

// Kind is the decision a signed record attests: one of the eight human
// decisions (O-16). The crawler never signs; its events have no Kind.
type Kind string

const (
	// KindApprove approves one exact digest of a tool.
	KindApprove Kind = "approve"
	// KindReject rejects one exact digest.
	KindReject Kind = "reject"
	// KindRollback returns a tool to an earlier approved digest.
	KindRollback Kind = "rollback"
	// KindDisable disables a tool whatever its version.
	KindDisable Kind = "disable"
	// KindEnable re-enables a disabled tool.
	KindEnable Kind = "enable"
	// KindPause pauses a server; no tool is named.
	KindPause Kind = "pause"
	// KindResume resumes a paused server; no tool is named.
	KindResume Kind = "resume"
	// KindBudgetReset resets a tool's proposal budget.
	KindBudgetReset Kind = "budget_reset"

	// kindList is the closed set as an error names it.
	kindList = "approve, reject, rollback, disable, enable, pause, resume, budget_reset"
)

// Valid reports whether k is one of the eight kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindApprove, KindReject, KindRollback, KindDisable, KindEnable, KindPause, KindResume, KindBudgetReset:
		return true
	}
	return false
}

// NamesVersion reports whether a decision of this kind carries a digest:
// approve, reject and rollback name one exact version; the others name none.
func (k Kind) NamesVersion() bool {
	return k == KindApprove || k == KindReject || k == KindRollback
}

// NamesTool reports whether a decision of this kind carries a tool name:
// every kind but pause and resume, which act on a server.
func (k Kind) NamesTool() bool {
	return k.Valid() && k != KindPause && k != KindResume
}

// Decision is the TypeDecision payload: what one person decided, for which
// catalog, on top of which audit head, with which key. Every field is present
// in the signed bytes, empty where the kind names nothing, so there is one
// shape per type. SignedAt is the signer's clock and informational; PrevHead
// is the freshness token the catalog compares and sets.
type Decision struct {
	Actor    string
	Catalog  string
	Digest   string
	Kind     Kind
	PrevHead string
	Server   string
	SignedAt time.Time
	Signer   string
	Tool     string
}

// decisionView is the JSON shape of a decision, keys in the order RFC 8785
// sorts them; the canonicaliser fixes the rest.
type decisionView struct {
	Actor    string `json:"actor"`
	Catalog  string `json:"catalog"`
	Digest   string `json:"digest"`
	Kind     string `json:"kind"`
	PrevHead string `json:"prev_head"`
	Server   string `json:"server"`
	SignedAt string `json:"signed_at"`
	Signer   string `json:"signer"`
	Tool     string `json:"tool"`
	Type     string `json:"type"`
}

// decisionKeys is the exact key set ParseDecision accepts.
func decisionKeys() []string {
	return []string{"actor", "catalog", "digest", "kind", "prev_head", "server", "signed_at", "signer", "tool", "type"}
}

// validate applies the field rules shared by MarshalDecision and
// ParseDecision, so the writer and the reader cannot drift apart.
func (d Decision) validate() error {
	switch {
	case !isActorName(d.Actor):
		return fmt.Errorf("%w: actor %s must match ^[a-z0-9][a-z0-9._@-]{0,63}$", ErrPayload, strconv.Quote(d.Actor))
	case !isLowerHex(d.Catalog, catalogIdentityHexLen):
		return fmt.Errorf("%w: catalog must be %d lower-case hex digits", ErrPayload, catalogIdentityHexLen)
	case !d.Kind.Valid():
		return fmt.Errorf("%w: kind %s is not one of %s", ErrPayload, strconv.Quote(string(d.Kind)), kindList)
	case !isLowerHex(d.PrevHead, hexDigestLen):
		return fmt.Errorf("%w: prev_head must be %d lower-case hex digits", ErrPayload, hexDigestLen)
	case !isServerName(d.Server):
		return fmt.Errorf("%w: server %s must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ within %d bytes", ErrPayload, strconv.Quote(d.Server), maxServerNameLen)
	case !isFingerprint(d.Signer):
		return fmt.Errorf("%w: signer must be a SHA256: fingerprint", ErrPayload)
	}
	if d.Kind.NamesVersion() {
		if !isLowerHex(d.Digest, hexDigestLen) {
			return fmt.Errorf("%w: a %s names a digest of %d lower-case hex digits", ErrPayload, d.Kind, hexDigestLen)
		}
	} else if d.Digest != "" {
		return fmt.Errorf("%w: a %s names no digest", ErrPayload, d.Kind)
	}
	if d.Kind.NamesTool() {
		if err := toolname.Validate(d.Tool); err != nil {
			return fmt.Errorf("%w: a %s names a tool: %v", ErrPayload, d.Kind, err)
		}
	} else if d.Tool != "" {
		return fmt.Errorf("%w: a %s names no tool", ErrPayload, d.Kind)
	}
	return nil
}

// MarshalDecision produces the exact bytes that are signed and stored: the RFC
// 8785 form of the decision with its type. It is called once per decision;
// the catalog stores its output verbatim and never rebuilds it.
func MarshalDecision(d Decision) ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	signedAt, err := formatSignedAt(d.SignedAt)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(decisionView{
		Actor: d.Actor, Catalog: d.Catalog, Digest: d.Digest, Kind: string(d.Kind),
		PrevHead: d.PrevHead, Server: d.Server, SignedAt: signedAt, Signer: d.Signer,
		Tool: d.Tool, Type: TypeDecision,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	canon, err := gate.Canonical(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	return canon, nil
}

// ParseDecision reads a decision from bytes whose signature already verified.
// It accepts exactly what MarshalDecision writes: TypeDecision as the type
// (read first; a trust list under this parser is ErrType), the canonical form,
// the ten keys and no other, string values within their caps, and a kind whose
// digest and tool fields agree with it.
func ParseDecision(b []byte) (Decision, error) {
	m, err := parsePayloadObject(b, TypeDecision, decisionKeys())
	if err != nil {
		return Decision{}, err
	}
	fields := make(map[string]string, len(m))
	for k := range m {
		s, err := stringField(m, k)
		if err != nil {
			return Decision{}, err
		}
		fields[k] = s
	}
	signedAt, err := parseSignedAt(fields["signed_at"])
	if err != nil {
		return Decision{}, err
	}
	d := Decision{
		Actor: fields["actor"], Catalog: fields["catalog"], Digest: fields["digest"],
		Kind: Kind(fields["kind"]), PrevHead: fields["prev_head"], Server: fields["server"],
		SignedAt: signedAt, Signer: fields["signer"], Tool: fields["tool"],
	}
	if err := d.validate(); err != nil {
		return Decision{}, err
	}
	return d, nil
}
