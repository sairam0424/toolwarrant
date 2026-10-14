package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/export"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const flagPubKey = "--pub-key"

// exportCommands is the table behind "export verify". "export" itself runs
// runExport, which hands the first argument to this table when it names a
// subcommand.
func exportCommands() []*command {
	return []*command{
		{name: "verify", synopsis: "export verify --dir DIR --pub-key FILE [--expect-head HEX]", summary: "check a signed export with the public key you hold: the signature over " + manifestFile + ", every listed file against its digest, and that the files on disk are exactly the files listed (opens no database)", run: runExportVerify},
	}
}

// runExportVerify checks an export directory against the signer's public key
// the operator keeps outside the export (D21 e). It opens no database: the
// check is of the mirror against the key, and it fails closed on a changed,
// missing, extra or renamed file, a signature over another manifest, a
// recorded key other than the one given, and, with --expect-head, a manifest
// that records another audit head than the one recorded when the export was
// made.
func runExportVerify(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	dir := fs.String("dir", "", "the export directory to check (required)")
	pubKey := fs.String("pub-key", "", "PKIX PEM file holding the signer's Ed25519 public key, kept outside the export directory (required)")
	expect := fs.String("expect-head", "", "fail unless "+manifestFile+" records this audit head, the one the export printed and audit verify showed at the time")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if err := requireFlag(c, *dir, "dir", "name the export directory to check"); err != nil {
		return err
	}
	if err := requireFlag(c, *pubKey, "pub-key", "name the file holding the signer's public key"); err != nil {
		return err
	}
	pub, err := loadPublicKey(*pubKey)
	if err != nil {
		return err
	}
	rep, err := export.Verify(*dir, pub, *expect)
	if err != nil {
		return fmt.Errorf("export in %s does not verify: %w", textdiff.Escape(*dir), err)
	}
	a.stdout.printf("export ok: %d files in %s match %s, which the key in %s signed\n", rep.Files, textdiff.Escape(*dir), manifestFile, textdiff.Escape(*pubKey))
	a.printVerifiedHead(rep, *expect)
	return a.stdout.broken()
}

// loadPublicKey reads the --pub-key file through the CLI's file rules (a
// regular file, no link followed, no pipe waited on) under the export
// package's own bound for a PEM key file, the one it applies to the key an
// export records, and parses it as one PKIX Ed25519 public key.
func loadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readRegularFile(path, flagPubKey, pemPublicKeyNoun, export.MaxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	pub, err := export.ParsePublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", flagPubKey, textdiff.Escape(path), err)
	}
	return pub, nil
}

// printVerifiedHead prints the catalog fields the manifest records, or says
// that a version 2 manifest records none, and reminds the operator to compare
// the head with the recorded one when no expectation was given.
func (a *app) printVerifiedHead(rep export.VerifyReport, expect string) {
	if rep.AuditHead == "" {
		a.stdout.printf("%s is version %d and records no audit head; export again to bind the export to the log\n", manifestFile, rep.Version)
		return
	}
	a.stdout.printf("%s records audit head %s and digest profile %s\n", manifestFile, rep.AuditHead, rep.DigestProfile)
	if expect == "" {
		a.stdout.printf("compare the head with the one you recorded when you exported, or pass it with --expect-head\n")
	}
}
