package main

import (
	"fmt"
	"strconv"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// noTrustListLine is what trust show prints on a catalog without a list; the
// catalog serves as v0.3 did, which is known limit L13 until trust init runs.
const noTrustListLine = "no trust list; decisions are attributed by name only (L13); run \"" + programName + " trust init\""

// trustShowJSON is trust show --json: the list in force as the walk verified
// it. in_force is false, and every other field empty, without a list.
type trustShowJSON struct {
	InForce         bool              `json:"in_force"`
	Version         int               `json:"version"`
	ListEntry       int64             `json:"list_entry"`
	BootstrapEntry  int64             `json:"bootstrap_entry"`
	Root            string            `json:"root"`
	SignedDecisions int               `json:"signed_decisions"`
	Lists           int               `json:"lists"`
	Signers         []trustSignerJSON `json:"signers"`
}

// trustSignerJSON is one operator of the list: the name, the key line the list
// stores (the one place besides --allowed-signers where a public key is
// printed), its fingerprint and type, and the trust entry that first named
// the key.
type trustSignerJSON struct {
	Name        string `json:"name"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	SinceEntry  int64  `json:"since_entry"`
}

// runTrustShow prints the trust list in force. The text form is a header and
// a table; --allowed-signers writes the file stock ssh-keygen -Y verify reads
// (one line per key, both namespaces); --json the view. Without a list the
// command says so and exits 0: that is a state, not a failure.
func runTrustShow(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	asJSON := fs.Bool("json", false, "print JSON")
	allowed := fs.Bool("allowed-signers", false, "print the allowed_signers file for ssh-keygen -Y verify -f")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if *asJSON && *allowed {
		return &usageError{msg: "--json and --allowed-signers are exclusive", cmd: c}
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	view, err := store.TrustList(a.ctx)
	if err != nil {
		return err
	}
	switch {
	case *allowed:
		return a.printAllowedSigners(view)
	case *asJSON:
		since, err := signerSince(a, store, view)
		if err != nil {
			return err
		}
		return writeJSON(a.stdout, trustJSONOf(view, since))
	case !view.InForce():
		a.stdout.printf("%s\n", noTrustListLine)
		return nil
	}
	return a.printTrustTable(store, view)
}

// printAllowedSigners renders the list in force through internal/trust, so
// the file is the one its ssh-keygen interop test accepts; without a list the
// file is empty and the state goes to stderr, so stdout stays a valid file.
func (a *app) printAllowedSigners(view catalog.TrustView) error {
	if !view.InForce() {
		a.stderr.printf("%s\n", noTrustListLine)
		return nil
	}
	rec, err := trust.Validate(signing.TrustList{Version: view.Version, Threshold: trust.Threshold, Signers: signersOf(view.Signers)})
	if err != nil {
		return fmt.Errorf("render the trust list: %w", err)
	}
	lines, err := trust.AllowedSigners(rec)
	if err != nil {
		return fmt.Errorf("render the trust list: %w", err)
	}
	a.stdout.print(string(lines))
	return a.stdout.broken()
}

// printTrustTable prints the header and one row per operator.
func (a *app) printTrustTable(store *catalog.Store, view catalog.TrustView) error {
	since, err := signerSince(a, store, view)
	if err != nil {
		return err
	}
	a.stdout.printf("trust list v%d (entry %d), root %s (entry %d), signed records: %d decisions, %d lists\n",
		view.Version, view.ListSeq, view.Root, view.BootstrapSeq, view.SignedDecisions, view.Lists)
	t := newTable(a.stdout)
	t.row("NAME", "FINGERPRINT", "TYPE", "SINCE")
	for _, op := range view.Signers {
		t.row(cell(op.Name), op.Fingerprint, keyType(op.Key), "entry "+strconv.FormatInt(since[op.Fingerprint], 10))
	}
	return t.flush()
}

// trustJSONOf renders the view with the entry each key was first listed at.
func trustJSONOf(view catalog.TrustView, since map[string]int64) trustShowJSON {
	out := trustShowJSON{InForce: view.InForce(), Version: view.Version, ListEntry: view.ListSeq, BootstrapEntry: view.BootstrapSeq,
		Root: view.Root, SignedDecisions: view.SignedDecisions, Lists: view.Lists, Signers: []trustSignerJSON{}}
	for _, op := range view.Signers {
		out.Signers = append(out.Signers, trustSignerJSON{Name: op.Name, Key: op.Key, Fingerprint: op.Fingerprint, Type: keyType(op.Key), SinceEntry: since[op.Fingerprint]})
	}
	return out
}

// keyType is the key's algorithm name, the first word of its canonical line.
func keyType(key string) string {
	pub, err := signing.ParseAuthorizedKey(key)
	if err != nil {
		return emptyCell
	}
	return pub.Type()
}

// signerSince finds, for every key of the list in force, the trust entry that
// first named it: the trust entries are read through the catalog's subject
// index (Store.TrustEntries: as many as the list has had versions, however
// long the log), their records through the checked read behind audit list
// --json, and each list parsed. The map is empty without a list.
func signerSince(a *app, store *catalog.Store, view catalog.TrustView) (map[string]int64, error) {
	since := map[string]int64{}
	if !view.InForce() {
		return since, nil
	}
	entries, err := store.TrustEntries(a.ctx)
	if err != nil {
		return nil, err
	}
	seqs := make([]int64, 0, len(entries))
	for _, e := range entries {
		seqs = append(seqs, e.Seq)
	}
	records, err := store.SignedRecords(a.ctx, seqs)
	if err != nil {
		return nil, err
	}
	for _, seq := range seqs {
		rec, ok := records[seq]
		if !ok {
			return nil, fmt.Errorf("%w: trust entry %d carries no signed record", catalog.ErrCorrupt, seq)
		}
		list, err := signing.ParseTrustList(rec.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: trust entry %d: %w", catalog.ErrCorrupt, seq, err)
		}
		noteFirstListing(since, list, seq)
	}
	return since, nil
}

// noteFirstListing records seq as the first entry naming each key of list
// that has none yet.
func noteFirstListing(since map[string]int64, list signing.TrustList, seq int64) {
	for _, s := range list.Signers {
		pub, err := signing.ParseAuthorizedKey(s.Key)
		if err != nil {
			continue
		}
		if fp := signing.Fingerprint(pub); since[fp] == 0 {
			since[fp] = seq
		}
	}
}
