package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The fixtures of the signed-flow tests: a crawled catalog, an in-process
// ssh-agent holding alice's key, throwaway Ed25519 keys for alice and bob as
// .pub files (the agent path) and as private key files (the file path), all
// made at run time under the test's directory, so no key material is in the
// tree; a FIDO2-shaped agent for the touch hint; and the raw-SQL append of a
// correctly sealed entry, which is what whoever can write the file can do.

const (
	skApplication = "ssh:"
	// auditColumns is the catalog's column list, repeated so the forgeries
	// below insert exactly what the catalog's reader scans.
	auditColumns = `seq, ts, actor, actor_type, event, subject, before_hash, after_hash, detail, prev_hash, hash`
	// catalogTimeLayout is the catalog's own TS spelling.
	catalogTimeLayout = "2006-01-02T15:04:05.000000000Z"
)

var (
	rootLine    = regexp.MustCompile(`record the trust root (SHA256:[A-Za-z0-9+/]{43}) with the audit head ([0-9a-f]{64})`)
	signedLine  = regexp.MustCompile(`signed as ([a-z0-9._@-]+) with (SHA256:[A-Za-z0-9+/]{43}) over head ([0-9a-f]{64}); audit head now ([0-9a-f]{64})`)
	entryAtLine = regexp.MustCompile(`recorded at entry (\d+)`)
)

// signedLab is a crawled catalog with an agent holding alice's key and the
// key files of alice and bob.
type signedLab struct {
	*cli
	u                                    *upstream
	sock                                 string
	addKey                               func(sigtest.Key)
	alice, bob                           sigtest.Key
	alicePub, bobPub, aliceFile, bobFile string
}

func newSignedLab(t *testing.T) *signedLab {
	t.Helper()
	c, u := fixture(t)
	sock, add := sigtest.NewAgent(t)
	dir := t.TempDir()
	l := &signedLab{cli: c, u: u, sock: sock, addKey: add, alice: sigtest.GenerateEd25519(t), bob: sigtest.GenerateEd25519(t)}
	add(l.alice)
	l.alicePub = sigtest.WritePublicKey(t, dir, "alice.pub", l.alice)
	l.bobPub = sigtest.WritePublicKey(t, dir, "bob.pub", l.bob)
	l.aliceFile = sigtest.WriteKeyFile(t, dir, "alice.key", l.alice)
	l.bobFile = sigtest.WriteKeyFile(t, dir, "bob.key", l.bob)
	c.env[envAuthSock] = sock
	return l
}

// fpOf is a key's fingerprint, the only key text any output may hold.
func fpOf(k sigtest.Key) string { return signing.Fingerprint(k.Public) }

// bootstrap runs trust init as alice through the agent and returns the root
// and the head the command printed.
func (l *signedLab) bootstrap(t *testing.T) (root, head string) {
	t.Helper()
	out := l.ok("--as", "alice", "--ssh-key", l.alicePub, "trust", "init")
	m := rootLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("trust init printed no root line:\n%s", out)
	}
	return m[1], m[2]
}

// signedAs parses the line a signed decision prints.
func signedAs(t *testing.T, out string) (actor, fp, over, head string) {
	t.Helper()
	m := signedLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no signed line in:\n%s", out)
	}
	return m[1], m[2], m[3], m[4]
}

// verifiedHead is the head audit verify prints.
func (c *cli) verifiedHead() string {
	c.t.Helper()
	m := headLine.FindStringSubmatch(c.ok("audit", "verify"))
	if m == nil {
		c.t.Fatal("audit verify printed no head")
	}
	return m[2]
}

// runHooked runs one command with a hook between a signature and the write
// that follows it, as the tests of the compare-and-set need.
func (c *cli) runHooked(hook func(), args ...string) result {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	var out, errb bytes.Buffer
	a := &app{ctx: ctx, stdin: strings.NewReader(""), stdout: &stream{w: &out}, stderr: &stream{w: &errb}, getenv: c.getenv, afterSign: hook}
	code := a.checkStreams(a.exitCode(a.dispatch(append([]string{"--db", c.db}, args...))))
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

// appendSealed appends e, correctly sealed from the file's head, through a
// raw handle and bumps the generation as any write would: the access D14
// grants to whoever can write the file. The seq and the time are filled in.
func appendSealed(t *testing.T, path string, e audit.Entry) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT ` + auditColumns + ` FROM audit_log ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	var prev audit.Entry
	for rows.Next() {
		var cur audit.Entry
		if err := rows.Scan(&cur.Seq, &cur.TS, &cur.Actor, &cur.ActorType, &cur.Event, &cur.Subject, &cur.BeforeHash, &cur.AfterHash, &cur.Detail, &cur.PrevHash, &cur.Hash); err != nil {
			t.Fatal(err)
		}
		prev = cur
	}
	_ = rows.Close()
	e.Seq, e.TS = prev.Seq+1, time.Now().UTC().Format(catalogTimeLayout)
	sealed, err := audit.Seal(prev, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO audit_log (`+auditColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sealed.Seq, sealed.TS, sealed.Actor, sealed.ActorType, sealed.Event, sealed.Subject, sealed.BeforeHash, sealed.AfterHash, sealed.Detail, sealed.PrevHash, sealed.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE meta SET value = value + 1 WHERE key = 'generation'`); err != nil {
		t.Fatal(err)
	}
	return sealed.Seq
}

// forgedApproval is a version.approved entry about server/tool approving
// digest by actor, shaped as the catalog writes one from pending_review and
// carrying no signed= token: what a forger without a key appends.
func forgedApproval(actor, server, tool, digest string) audit.Entry {
	return audit.Entry{Actor: actor, ActorType: "human", Event: "version.approved", Subject: server + "/" + tool, AfterHash: digest,
		Detail: "digest=" + digest + " state=pending_review->enabled last_seen=" + digest + " proposals=0->0"}
}

// replaceSignedRecord rewrites the payload of the signed record at seq under
// its guard, dropped and put back, so only the forgery remains.
func replaceSignedRecord(t *testing.T, path string, seq int64) {
	t.Helper()
	var ddl string
	queryRow(t, path, "SELECT sql FROM sqlite_master WHERE name = 'signed_records_no_update'", &ddl)
	execSQL(t, path, "DROP TRIGGER signed_records_no_update", "UPDATE signed_records SET payload = X'7b7d' WHERE seq = "+itoa(seq), ddl)
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// keyMaterial lists the strings no output may carry for k: the PEM marker,
// the base64 of the seed and of the whole private key, and every body line of
// the private key file at path (the OpenSSH container with its random check
// bytes). The public key's base64 is returned apart, since two commands
// print it on purpose.
func keyMaterial(t *testing.T, k sigtest.Key, path string) (private []string, public string) {
	t.Helper()
	priv, ok := k.Private.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("keyMaterial wants an Ed25519 key")
	}
	private = []string{"PRIVATE KEY", base64.StdEncoding.EncodeToString(priv.Seed()), base64.StdEncoding.EncodeToString(priv)}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") {
			private = append(private, line)
		}
	}
	return private, base64.StdEncoding.EncodeToString(k.Public.Marshal())
}

// skAgent is an Ed25519 key dressed as a FIDO2 key (sk-ssh-ed25519@openssh.com)
// served by an agent that signs as a security key does (PROTOCOL.u2f: the
// application and message digests, the user-presence flag and a counter), so
// the CLI prints the touch hint for it and the signature verifies under
// x/crypto's sk verifier and the signing package's policy.
type skAgent struct {
	mu      sync.Mutex
	priv    ed25519.PrivateKey
	pub     ssh.PublicKey
	counter uint32
}

// newSKAgent serves an skAgent and returns its socket and the key's public
// half.
func newSKAgent(t *testing.T) (sock string, pub ssh.PublicKey) {
	t.Helper()
	edPub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := ssh.Marshal(struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{ssh.KeyAlgoSKED25519, edPub, skApplication})
	pub, err = ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return sigtest.Serve(t, &skAgent{priv: priv, pub: pub}), pub
}

func (a *skAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{{Format: a.pub.Type(), Blob: a.pub.Marshal(), Comment: "sk"}}, nil
}

// Sign signs as a security key: the signed message is H(application), the
// flags, the counter and H(data); the signature carries the flags and the
// counter after the Ed25519 signature.
func (a *skAgent) Sign(_ ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counter++
	appDigest, dataDigest := sha256.Sum256([]byte(skApplication)), sha256.Sum256(data)
	msg := ssh.Marshal(struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{appDigest[:], 1, a.counter, dataDigest[:]})
	rest := ssh.Marshal(struct {
		Flags   byte
		Counter uint32
	}{1, a.counter})
	return &ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(a.priv, msg), Rest: rest}, nil
}

func (a *skAgent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return a.Sign(key, data)
}
func (a *skAgent) Add(agent.AddedKey) error       { return agent.ErrExtensionUnsupported }
func (a *skAgent) Remove(ssh.PublicKey) error     { return agent.ErrExtensionUnsupported }
func (a *skAgent) RemoveAll() error               { return agent.ErrExtensionUnsupported }
func (a *skAgent) Lock([]byte) error              { return agent.ErrExtensionUnsupported }
func (a *skAgent) Unlock([]byte) error            { return agent.ErrExtensionUnsupported }
func (a *skAgent) Signers() ([]ssh.Signer, error) { return nil, agent.ErrExtensionUnsupported }
func (a *skAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
