package trust

import (
	"reflect"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// A zero State refuses a rotation (ErrNoList), accepts a bootstrap and
// records its seq as both BootstrapSeq and ListSeq, refuses a second bootstrap
// (ErrSecondBootstrap) naming the first, folds a rotation moving ListSeq and
// keeping BootstrapSeq, and applies the rotation rule to the next record
// (a repeat of version 2 is ErrRollback).
func TestState_FoldsBootstrapAndRotationsAndRefusesASecondBootstrapOrARotationBeforeOne(t *testing.T) {
	t.Parallel()
	a, b := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	v1 := mustValidate(t, listOf(1, named{"alice", a}))
	v2 := mustValidate(t, listOf(2, named{"alice", a}, named{"bob", b}))
	var s State
	_, err := s.Apply(5, KindRotated, v2, fp(a), "")
	wantErrIs(t, "a rotation before any bootstrap", err, ErrNoList, "")
	s1, err := s.Apply(5, KindBootstrap, v1, fp(a), "")
	if err != nil || !reflect.DeepEqual(s1, State{Current: &v1, BootstrapSeq: 5, ListSeq: 5}) {
		t.Fatalf("bootstrap at 5 = %+v, %v", s1, err)
	}
	_, err = s1.Apply(9, KindBootstrap, v1, fp(a), "")
	wantErrIs(t, "a second bootstrap", err, ErrSecondBootstrap, "started at seq 5")
	s2, err := s1.Apply(9, KindRotated, v2, fp(a), "")
	if err != nil || !reflect.DeepEqual(s2, State{Current: &v2, BootstrapSeq: 5, ListSeq: 9}) {
		t.Fatalf("rotation at 9 = %+v, %v", s2, err)
	}
	_, err = s2.Apply(12, KindRotated, v2, fp(a), "")
	wantErrIs(t, "version 2 again", err, ErrRollback, "")
	v3 := mustValidate(t, listOf(3, named{"bob", b}))
	s3, err := s2.Apply(12, KindRotated, v3, fp(b), "")
	if err != nil || !reflect.DeepEqual(s3, State{Current: &v3, BootstrapSeq: 5, ListSeq: 12}) {
		t.Fatalf("bob removes alice with his own key, which is in both lists: %+v, %v", s3, err)
	}
	if name, ok := s3.Current.Lookup(fp(a)); ok || name != "" {
		t.Errorf("alice's key is still named after her removal: %q", name)
	}
}

// Apply refuses an event that is neither kind, a seq below 1 and a seq not
// above the seq of the list in force, honours the pinned root on the
// bootstrap only, and leaves the receiver unchanged on every refusal, so a
// walk keeps the state it had.
func TestState_RefusesAnUnknownKindAndASeqOutOfOrderAndLeavesTheReceiverUnchanged(t *testing.T) {
	t.Parallel()
	a, b := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	v1 := mustValidate(t, listOf(1, named{"alice", a}))
	v2 := mustValidate(t, listOf(2, named{"alice", a}, named{"bob", b}))
	s1, err := State{}.Apply(3, KindBootstrap, v1, fp(a), fp(a))
	if err != nil {
		t.Fatal(err)
	}
	before := State{Current: &v1, BootstrapSeq: 3, ListSeq: 3}
	_, err = State{}.Apply(3, KindBootstrap, v1, fp(a), fp(b))
	wantErrIs(t, "bootstrap under another root", err, ErrNotThePinnedRoot, "")
	kept, err := s1.Apply(4, Kind("decision.signed"), v2, fp(a), "")
	wantErrIs(t, "another event", err, ErrKind, `"decision.signed"`)
	if !reflect.DeepEqual(kept, s1) {
		t.Errorf("a refused record returned %+v, not the receiver %+v", kept, s1)
	}
	_, err = s1.Apply(4, "", v2, fp(a), "")
	wantErrIs(t, "an empty kind", err, ErrKind, "")
	_, err = s1.Apply(3, KindRotated, v2, fp(a), "")
	wantErrIs(t, "the same seq", err, ErrSeqOrder, "seq 3 after seq 3")
	_, err = s1.Apply(2, KindRotated, v2, fp(a), "")
	wantErrIs(t, "an earlier seq", err, ErrSeqOrder, "")
	_, err = State{}.Apply(0, KindBootstrap, v1, fp(a), "")
	wantErrIs(t, "seq 0", err, ErrSeqOrder, "")
	_, err = State{}.Apply(-1, KindBootstrap, v1, fp(a), "")
	wantErrIs(t, "seq -1", err, ErrSeqOrder, "")
	if s2, err := s1.Apply(4, KindRotated, v2, fp(a), fp(b)); err != nil || s2.ListSeq != 4 {
		t.Errorf("a rotation ignores the pinned root, which is the bootstrap's: %+v, %v", s2, err)
	}
	if !reflect.DeepEqual(s1, before) {
		t.Errorf("the receiver changed: %+v", s1)
	}
}
