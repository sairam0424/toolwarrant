package export

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// maxReportedNames bounds how many file names one refusal lists; the rest
	// are counted.
	maxReportedNames = 5
	// maxQuotedName bounds a file name quoted in an error; the names on disk
	// are whatever the directory holds, not only this package's encoded ones.
	maxQuotedName = 120
)

// VerifyReport is what Verify established about an export directory.
type VerifyReport struct {
	// Version is the manifest version found: 3, or 2 from before the catalog
	// fields.
	Version int
	// Files is the number of tool files whose bytes hashed to their digest.
	Files int
	// AuditHead and DigestProfile are the catalog fields the manifest
	// records; both are empty for a version 2 manifest.
	AuditHead     string
	DigestProfile string
}

// Verify checks a signed export in dir against the public key the operator
// holds: MANIFEST.json must be complete and one this package wrote,
// MANIFEST.json.pub must record exactly pub, MANIFEST.json.sig must be pub's
// signature over the exact bytes of MANIFEST.json, every listed file's bytes
// must hash to its digest, and the files on disk must be exactly the files
// listed plus the manifest and its two signature files (a top-level .git
// directory is the repository Commit keeps and is skipped). With expectHead,
// the manifest's audit head must equal it. Everything fails closed: an extra,
// missing or renamed file, a symlink, a nested directory, a stale signature or
// a manifest from another key is an error that names what was found. Nothing
// is written.
func Verify(dir string, pub ed25519.PublicKey, expectHead string) (VerifyReport, error) {
	if len(pub) != ed25519.PublicKeySize {
		return VerifyReport{}, errors.New("export: the public key is not an Ed25519 key")
	}
	root, err := openExistingRoot(dir)
	if err != nil {
		return VerifyReport{}, err
	}
	defer func() { _ = root.Close() }()
	raw, doc, err := readCompleteManifest(root)
	if err != nil {
		return VerifyReport{}, err
	}
	if err := checkRecordedKey(root, pub); err != nil {
		return VerifyReport{}, err
	}
	sig, err := readSignature(root)
	if err != nil {
		return VerifyReport{}, err
	}
	if !ed25519.Verify(pub, raw, sig) {
		return VerifyReport{}, errors.New("export: " + signatureName + " is not a signature over " + manifestName + " by the key given; the manifest or the signature changed after the export, or another key signed it")
	}
	if err := checkExpectedHead(doc, expectHead); err != nil {
		return VerifyReport{}, err
	}
	if err := checkListedFiles(root, doc); err != nil {
		return VerifyReport{}, err
	}
	if err := checkFileSet(root, doc); err != nil {
		return VerifyReport{}, err
	}
	return VerifyReport{Version: doc.Version, Files: len(doc.Tools), AuditHead: doc.AuditHead, DigestProfile: doc.DigestProfile}, nil
}

// openExistingRoot opens dir as an os.Root without creating it: Verify reads
// a directory an export made and refuses anything else, a symlink included.
func openExistingRoot(dir string) (*os.Root, error) {
	if dir == "" {
		return nil, errors.New("export: directory is empty")
	}
	clean := filepath.Clean(dir)
	fi, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("export: stat directory: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return nil, errors.New("export: directory is a symlink or not a directory")
	}
	root, err := os.OpenRoot(clean)
	if err != nil {
		return nil, fmt.Errorf("export: open directory: %w", err)
	}
	return root, nil
}

// readCompleteManifest reads MANIFEST.json for verification: a regular file of
// sane size, parsed by this package's own rule, and complete.
func readCompleteManifest(root *os.Root) ([]byte, manifestDoc, error) {
	raw, exists, err := readSmallFile(root, manifestName, maxManifestBytes)
	if err != nil {
		return nil, manifestDoc{}, err
	}
	if !exists {
		return nil, manifestDoc{}, errors.New("export: " + manifestName + " not found; the directory is not an export")
	}
	doc, ok := parseManifest(raw)
	if !ok {
		return nil, manifestDoc{}, errors.New("export: " + manifestName + " is not a manifest this version reads")
	}
	if doc.Status != statusComplete {
		return nil, manifestDoc{}, errors.New("export: " + manifestName + " is pending: the last export did not finish, run it again")
	}
	return raw, doc, nil
}

// checkRecordedKey requires MANIFEST.json.pub to record exactly the key the
// verifier holds. A directory whose recorded key is another one was signed by
// somebody else or re-signed after a rewrite; its signature is not even tried.
func checkRecordedKey(root *os.Root, pub ed25519.PublicKey) error {
	recorded, err := readRecordedPublicKey(root)
	if err != nil {
		return err
	}
	if !recorded.Equal(pub) {
		return errors.New("export: " + publicKeyName + " records another public key than the one given; the export was signed by another key")
	}
	return nil
}

// checkExpectedHead compares the manifest's audit head with the one the
// operator recorded, when one was given. The expectation must itself be a
// hex sha256; a version 2 manifest has no head to compare.
func checkExpectedHead(doc manifestDoc, expectHead string) error {
	if expectHead == "" {
		return nil
	}
	want := strings.ToLower(expectHead)
	if !isHexDigest(want) {
		return errors.New("export: the expected audit head is not a hex sha256")
	}
	if doc.Version == manifestVersionNoHead {
		return errors.New("export: " + manifestName + " is version 2 and records no audit head to compare with")
	}
	if doc.AuditHead != want {
		return fmt.Errorf("export: audit head mismatch: %s records %s, expected %s; the export mirrors another state of the log than the head you recorded", manifestName, doc.AuditHead, want)
	}
	return nil
}

// checkListedFiles reads every file the manifest lists and requires its bytes,
// less the trailing newline Write adds, to hash to the listed digest.
func checkListedFiles(root *os.Root, doc manifestDoc) error {
	for _, e := range doc.Tools {
		if !isHexDigest(e.Digest) {
			return fmt.Errorf("export: %s lists %s with a digest that is not a lower-case hex sha256", manifestName, quoteName(e.File))
		}
		data, exists, err := readSmallFile(root, filepath.FromSlash(e.File), maxToolBytes+1)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("export: %s is listed in %s but missing", quoteName(e.File), manifestName)
		}
		if len(data) == 0 || data[len(data)-1] != '\n' {
			return fmt.Errorf("export: %s does not end in the newline the export writes", quoteName(e.File))
		}
		sum := sha256.Sum256(data[:len(data)-1])
		if hex.EncodeToString(sum[:]) != e.Digest {
			return fmt.Errorf("export: %s does not hash to its digest %s; the file was changed after the export", quoteName(e.File), e.Digest)
		}
	}
	return nil
}

// checkFileSet walks the directory without following links and requires every
// entry to be accounted for: the manifest and its two signature files at the
// top, one directory per listed server, and inside it exactly the listed
// files. Anything else is named: an extra file, a nested directory, a symlink
// or another non-regular entry. Missing files were already reported by
// checkListedFiles.
func checkFileSet(root *os.Root, doc manifestDoc) error {
	listed, servers := listedSets(doc)
	var extra []string
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return fmt.Errorf("export: walk directory: %w", err)
		case p == ".":
			return nil
		case d.IsDir() && p == gitDirName:
			return fs.SkipDir
		case d.Type()&fs.ModeType != 0 && !d.IsDir():
			return fmt.Errorf("export: %s is a symlink or not a regular file", quoteName(p))
		}
		if entryAccountedFor(p, d.IsDir(), listed, servers) {
			return nil
		}
		extra = append(extra, p)
		if d.IsDir() {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(extra) > 0 {
		return fmt.Errorf("export: %s not listed in %s: %s", pluralEntries(len(extra)), manifestName, quoteNames(extra))
	}
	return nil
}

// listedSets returns the listed file paths and the listed server directories.
func listedSets(doc manifestDoc) (files, servers map[string]struct{}) {
	files = make(map[string]struct{}, len(doc.Tools))
	servers = make(map[string]struct{}, len(doc.Tools))
	for _, e := range doc.Tools {
		files[e.File] = struct{}{}
		servers[e.Server] = struct{}{}
	}
	return files, servers
}

// entryAccountedFor reports whether a walked entry (slash-separated, relative)
// is one the manifest explains: a top-level manifest or signature file, a
// listed server directory, or a listed tool file.
func entryAccountedFor(p string, isDir bool, files, servers map[string]struct{}) bool {
	if isDir {
		_, ok := servers[p]
		return ok && !strings.Contains(p, "/")
	}
	switch p {
	case manifestName, signatureName, publicKeyName:
		return true
	}
	_, ok := files[p]
	return ok
}

// quoteName quotes a file name from disk for an error, bounded in length.
func quoteName(name string) string {
	if len(name) > maxQuotedName {
		name = name[:maxQuotedName]
	}
	return strconv.Quote(name)
}

// quoteNames lists the first few names, then counts the rest.
func quoteNames(names []string) string {
	shown := names
	if len(shown) > maxReportedNames {
		shown = shown[:maxReportedNames]
	}
	quoted := make([]string, 0, len(shown))
	for _, n := range shown {
		quoted = append(quoted, quoteName(n))
	}
	out := strings.Join(quoted, ", ")
	if rest := len(names) - len(shown); rest > 0 {
		out += fmt.Sprintf(" and %d more", rest)
	}
	return out
}

// pluralEntries says how many unexpected entries were found.
func pluralEntries(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}
