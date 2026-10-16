package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// The trust commands (D22 (c) and (h); owner decisions O-11 to O-14). trust
// init writes the bootstrap, a version 1 list naming the acting person with
// the key that signs it; trust add and trust remove write the next version,
// signed by the acting person's key, which the rotation rule requires to be in
// both lists, so a key cannot sign its own removal and the last signer cannot
// be removed; trust show reads the list in force (trustshow.go). The signer is
// resolved before the catalog is opened, so a refused key changes nothing;
// every write goes through signedWrite, the compare-and-set with one retry.
const (
	flagKey          = "key"
	publicKeyNoun    = "SSH public key file"
	trustInitMeaning = "the key that signs the first trust list and becomes its root"
	trustEditMeaning = "a key the trust list in force names, which signs the new list"
)

// trustCommands is the table behind "trust".
func trustCommands() []*command {
	return []*command{
		{name: "init", synopsis: "trust init [--expect-head HEX]", summary: "record the first trust list: you, with the key --ssh-key names; from then on every decision must be signed by a listed key", run: runTrustInit},
		{name: "add", synopsis: "trust add NAME --key PUBKEY_FILE [--expect-head HEX]", summary: "add an operator's public key to the trust list, signed by your listed key", run: runTrustAdd},
		{name: "remove", synopsis: "trust remove NAME [--expect-head HEX]", summary: "remove an operator from the trust list, signed by another listed key; what their key signed before stands", run: runTrustRemove},
		{name: "show", synopsis: "trust show [--json | --allowed-signers]", summary: "show the trust list in force, as a table, as JSON or as the allowed_signers file ssh-keygen -Y verify reads", run: runTrustShow},
	}
}

// runTrustInit records the bootstrap. The acting person comes from --as or
// the OS user (there is no list yet to derive them from) and is never the
// system actor, refused with a sentence that names this command; the list
// names them with the key that signs it, so the bootstrap is self-signed and
// its signer is the root every later open may pin. A catalog that already has
// a list is refused: the list cannot start twice.
func runTrustInit(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	expect := fs.String(flagExpect, "", expectHelp)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	actor, err := a.humanActor(c, systemActorCannotInitTrust)
	if err != nil {
		return err
	}
	signer, err := a.requireSigner(c, trustInitMeaning)
	if err != nil {
		return err
	}
	defer signer.close()
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	r, err := a.signedWrite(*expect, func() (catalog.Receipt, error) {
		st, err := store.SigningState(a.ctx)
		if err != nil {
			return catalog.Receipt{}, err
		}
		if st.Trust.InForce() {
			return catalog.Receipt{}, fmt.Errorf("the catalog already has a trust list (v%d, in force since entry %d); use \"%s trust add\" or \"%s trust remove\" to change it", st.Trust.Version, st.Trust.ListSeq, programName, programName)
		}
		signers := []signing.Signer{{Key: signing.MarshalKey(signer.pub()), Name: actor.Name}}
		return a.setTrust(store, signer, *expect, st, trust.MinVersion, signers, actor)
	})
	if err != nil {
		return err
	}
	a.stdout.printf("trust list v%d recorded at entry %d: %s %s\n", trust.MinVersion, r.Seq, cell(actor.Name), signer.fp)
	a.stdout.printf("decisions from entry %d on must be signed by a listed key; record the trust root %s with the audit head %s outside the database and pass it as --%s (env %s) to every command and to serve\n",
		r.Seq+1, signer.fp, r.Head, flagTrustRoot, envTrustRoot)
	return nil
}

// runTrustAdd adds NAME with the public key in --key to the list in force.
// The name follows the rule of every actor and may not be the system actor's;
// the key file is read under the file rules, as ssh-keygen wrote it, and the
// key must be one the policy accepts. Duplicate names and keys are refused by
// the catalog.
func runTrustAdd(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	keyPath := fs.String(flagKey, "", "the operator's SSH public key file (.pub), as ssh-keygen writes it (required)")
	expect := fs.String(flagExpect, "", expectHelp)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "NAME"); err != nil {
		return err
	}
	name, err := operatorName(c, pos[0])
	if err != nil {
		return err
	}
	if err := requireFlag(c, *keyPath, flagKey, "name the operator's public key file"); err != nil {
		return err
	}
	pub, err := readPublicKeyFile(*keyPath)
	if err != nil {
		return err
	}
	r, view, actor, err := a.rotateTrust(c, *expect, func(ops []trust.Operator) ([]signing.Signer, error) {
		return append(signersOf(ops), signing.Signer{Key: signing.MarshalKey(pub), Name: name}), nil
	})
	if err != nil {
		return err
	}
	a.stdout.printf("trust list v%d recorded at entry %d: %s; signed as %s\n", view.Version, r.Seq, signerList(view.Signers), cell(actor.Name))
	return nil
}

// runTrustRemove removes NAME from the list in force. The last signer cannot
// be removed (a list is never emptied) and a key cannot sign its own removal
// (the rotation rule wants the signer in both lists); both are refused here
// with the fix before anything is signed, and by the catalog again.
func runTrustRemove(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	expect := fs.String(flagExpect, "", expectHelp)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "NAME"); err != nil {
		return err
	}
	name, err := operatorName(c, pos[0])
	if err != nil {
		return err
	}
	var signerFP string
	r, view, actor, err := a.rotateTrustAs(c, *expect, &signerFP, func(ops []trust.Operator) ([]signing.Signer, error) {
		i := slices.IndexFunc(ops, func(op trust.Operator) bool { return op.Name == name })
		switch {
		case i < 0:
			return nil, fmt.Errorf("%s is not in the trust list; run \"%s trust show\"", cell(name), programName)
		case len(ops) == 1:
			return nil, errors.New("the trust list must keep at least one signer; add another key before removing this one")
		case ops[i].Fingerprint == signerFP:
			return nil, errors.New("a key cannot sign its own removal; sign with a key that stays")
		}
		return signersOf(slices.Delete(slices.Clone(ops), i, i+1)), nil
	})
	if err != nil {
		return err
	}
	a.stdout.printf("trust list v%d recorded at entry %d: %s; signed as %s; decisions signed before this entry stand\n", view.Version, r.Seq, signerList(view.Signers), cell(actor.Name))
	return nil
}

// rotateTrust is rotateTrustAs for a caller that does not need the signer's
// fingerprint inside edit.
func (a *app) rotateTrust(c *command, expect string, edit func([]trust.Operator) ([]signing.Signer, error)) (catalog.Receipt, catalog.TrustView, catalog.Actor, error) {
	var fp string
	return a.rotateTrustAs(c, expect, &fp, edit)
}

// rotateTrustAs writes the next version of the list in force: the signer is
// resolved first (its fingerprint stored in fp for edit), then the catalog is
// opened, and on each attempt the list in force is read with the head, the
// acting person derived from the key, the new signers computed by edit and
// the list signed and recorded. It returns the receipt, the list now in
// force and the person who signed.
func (a *app) rotateTrustAs(c *command, expect string, fp *string, edit func([]trust.Operator) ([]signing.Signer, error)) (r catalog.Receipt, view catalog.TrustView, actor catalog.Actor, err error) {
	signer, err := a.requireSigner(c, trustEditMeaning)
	if err != nil {
		return catalog.Receipt{}, catalog.TrustView{}, catalog.Actor{}, err
	}
	defer signer.close()
	*fp = signer.fp
	label, err := a.decidingActor(c)
	if err != nil {
		return catalog.Receipt{}, catalog.TrustView{}, catalog.Actor{}, err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return catalog.Receipt{}, catalog.TrustView{}, catalog.Actor{}, err
	}
	defer closeStore(store, &err)
	r, err = a.signedWrite(expect, func() (catalog.Receipt, error) {
		st, err := store.SigningState(a.ctx)
		if err != nil {
			return catalog.Receipt{}, err
		}
		if !st.Trust.InForce() {
			return catalog.Receipt{}, fmt.Errorf("%w; run \"%s trust init\" first", catalog.ErrNoTrustList, programName)
		}
		if actor, err = a.signedActor(c, st.Trust, signer.fp, label, a.givenLabel()); err != nil {
			return catalog.Receipt{}, err
		}
		signers, err := edit(st.Trust.Signers)
		if err != nil {
			return catalog.Receipt{}, err
		}
		return a.setTrust(store, signer, expect, st, st.Trust.Version+1, signers, actor)
	})
	if err != nil {
		return catalog.Receipt{}, catalog.TrustView{}, catalog.Actor{}, err
	}
	if view, err = store.TrustList(a.ctx); err != nil {
		return catalog.Receipt{}, catalog.TrustView{}, catalog.Actor{}, err
	}
	return r, view, actor, nil
}

// setTrust is one attempt of a trust write: the expected head compared, the
// list built over the head st carries, signed under the trust namespace and
// recorded by SetTrust, whose compare-and-set refuses it when the head moved.
func (a *app) setTrust(store *catalog.Store, signer *cliSigner, expect string, st catalog.SigningState, version int, signers []signing.Signer, actor catalog.Actor) (catalog.Receipt, error) {
	if err := checkExpectedHead(expect, st.Head); err != nil {
		return catalog.Receipt{}, err
	}
	payload, err := signing.MarshalTrustList(signing.TrustList{
		Catalog: st.Identity, PrevHead: st.Head, SignedAt: time.Now(), Signer: signer.fp,
		Signers: signers, Threshold: trust.Threshold, Version: version,
	})
	if err != nil {
		return catalog.Receipt{}, fmt.Errorf("build the trust list to sign: %w", err)
	}
	rec, err := signer.sign(a.ctx, payload, signing.NamespaceTrust)
	if err != nil {
		return catalog.Receipt{}, err
	}
	a.afterSigning()
	return store.SetTrust(a.ctx, rec, actor)
}

// signersOf renders the operators of a view as the signers of the next list,
// in list order; the keys are the canonical lines the list already holds.
func signersOf(ops []trust.Operator) []signing.Signer {
	out := make([]signing.Signer, 0, len(ops)+1)
	for _, op := range ops {
		out = append(out, signing.Signer{Key: op.Key, Name: op.Name})
	}
	return out
}

// operatorName normalises the NAME of a trust command as every actor name is
// normalised and refuses the system actor's, which never signs.
func operatorName(c *command, raw string) (string, error) {
	name, err := normalizeActorName(raw)
	if err != nil {
		return "", err
	}
	if name == systemActorName {
		return "", &usageError{msg: fmt.Sprintf("%s is the system actor, which never signs; name a person", systemActorName), cmd: c}
	}
	return name, nil
}

// readPublicKeyFile reads one public key as ssh-keygen writes a .pub (`type
// base64 [comment]`, one line) under the file rules of every operator-given
// path and the signing package's size bound, refuses authorized_keys options
// and a key outside the policy, and returns the key. Only the key's canonical
// line (signing.MarshalKey) goes into the list; the comment is dropped. The
// path in a refusal is raw; describe escapes it once.
func readPublicKeyFile(path string) (ssh.PublicKey, error) {
	data, err := readRegularFile(path, "--"+flagKey, publicKeyNoun, signing.MaxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
	pub, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("--%s %s: not an SSH public key as ssh-keygen writes one (type, base64, optional comment): %w", flagKey, path, err)
	}
	if len(options) != 0 {
		return nil, fmt.Errorf("--%s %s: %w", flagKey, path, signing.ErrKeyOptions)
	}
	if err := signing.CheckKeyPolicy(pub); err != nil {
		return nil, fmt.Errorf("--%s %s: %w", flagKey, path, err)
	}
	return pub, nil
}
