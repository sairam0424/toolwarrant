//go:build e2e

package e2e

import (
	"database/sql"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
	_ "modernc.org/sqlite" // scenario S reaches into the catalog to forge entries

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The key material and the in-process ssh-agent of scenario S (signed
// decisions and the operator trust list, D22, limit L13). Every key is made by
// internal/signing/sigtest when the scenario runs and written owner-only under
// the work directory, as e2e/tlslab_test.go does with internal/testcert;
// nothing is in the tree. The agent is sigtest's keyring served on a unix
// socket under the work directory, so the CLI subprocesses find it through
// SSH_AUTH_SOCK and the developer's own agent is never asked to sign.
const (
	// sshDirName is the directory under the work directory that holds the key
	// files; sshDirMode keeps it owner-only, as the socket's rules want.
	sshDirName             = "ssh"
	sshDirMode os.FileMode = 0o700
	// agentSockName is the lab agent's socket under the work directory;
	// agentSockMode is what OpenSSH's own ssh-agent gives its socket.
	agentSockName             = "agent.sock"
	agentSockMode os.FileMode = 0o600
	// bob is the second operator of scenario S: enrolled by the reviewer,
	// approves with a key file and no agent, and is the key that stays when
	// the reviewer is removed and added back.
	bob = "bob"
	// auditColumns is the column list of the audit log, in the order the
	// catalog writes and the forgery reads it (internal/catalog/audit.go).
	auditColumns = `seq, ts, actor, actor_type, event, subject, before_hash, after_hash, detail, prev_hash, hash`
	// catalogTimeLayout is how the catalog spells an entry's timestamp
	// (internal/catalog/store.go timeLayout).
	catalogTimeLayout = "2006-01-02T15:04:05.000000000Z"
	// sqliteDriver is the driver name modernc.org/sqlite registers.
	sqliteDriver = "sqlite"
	// actorHuman and actorSystem are the two actor types an entry carries.
	actorHuman  = "human"
	actorSystem = "system"
	// crawler is the system actor's name, which crawl-shaped entries carry.
	crawler = "crawler"
)

// sshLab is the material of scenario S: the agent's socket, the reviewer's
// public key (the agent path), bob's public key and his unencrypted private
// key file (the key-file path), the three fingerprints, and what trust init
// printed once it ran.
type sshLab struct {
	sock                    string
	reviewerPub             string
	bobPub, bobKey          string
	reviewerFP, bobFP       string
	strangerFP              string
	root, initHead          string
	bootstrapSeq            int64
	reviewerKey, bobKeyPair sigtest.Key
}

// newSSHLab makes the keys, writes them under workdir/ssh and serves the
// agent holding both private keys for the rest of the run.
func newSSHLab(t *testing.T, s *stack) *sshLab {
	t.Helper()
	dir := filepath.Join(s.h.workdir, sshDirName)
	if err := os.Mkdir(dir, sshDirMode); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	lab := &sshLab{reviewerKey: sigtest.GenerateEd25519(t), bobKeyPair: sigtest.GenerateEd25519(t)}
	lab.reviewerPub = sigtest.WritePublicKey(t, dir, reviewer+".pub", lab.reviewerKey)
	lab.bobPub = sigtest.WritePublicKey(t, dir, bob+".pub", lab.bobKeyPair)
	lab.bobKey = sigtest.WriteKeyFile(t, dir, bob+".key", lab.bobKeyPair)
	lab.reviewerFP = signing.Fingerprint(lab.reviewerKey.Public)
	lab.bobFP = signing.Fingerprint(lab.bobKeyPair.Public)
	lab.strangerFP = signing.Fingerprint(sigtest.GenerateEd25519(t).Public)
	lab.sock = s.serveAgent(t, lab.reviewerKey, lab.bobKeyPair)
	return lab
}

// serveAgent serves sigtest's keyring agent, holding keys, on a 0600 unix
// socket under the work directory (or, when that path would exceed darwin's
// sun_path bound, in a private temporary directory) and keeps it alive until
// the root test ends: J to N sign through it after S.
func (s *stack) serveAgent(t *testing.T, keys ...sigtest.Key) string {
	t.Helper()
	sock := filepath.Join(s.h.workdir, agentSockName)
	if len(sock) >= signing.MaxSocketPathBytes {
		dir, err := os.MkdirTemp("", "tw-e2e-agent")
		if err != nil {
			t.Fatalf("create the agent's directory: %v", err)
		}
		s.root.Cleanup(func() { _ = os.RemoveAll(dir) })
		sock = filepath.Join(dir, agentSockName)
	}
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k.Private, Comment: "toolwarrant e2e"}); err != nil {
			t.Fatalf("add a key to the lab agent: %v", err)
		}
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen on %s: %v", sock, err)
	}
	if err := os.Chmod(sock, agentSockMode); err != nil {
		t.Fatalf("chmod %s: %v", sock, err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = agent.ServeAgent(keyring, c)
				_ = c.Close()
			}()
		}
	}()
	s.root.Cleanup(func() { _ = l.Close() })
	return sock
}

// catalogFiles are the catalog and its two SQLite side files, the three the
// backup copies and the restore puts back.
func (s *stack) catalogFiles() []string {
	return []string{s.db, s.db + "-wal", s.db + "-shm"}
}

// backupCatalog copies the catalog into a fresh directory under the work
// directory while no process has it open, the backup the recovery procedure
// restores after a forgery is found.
func (s *stack) backupCatalog(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(s.h.workdir, "backup-"+name)
	if err := os.Mkdir(dir, sshDirMode); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	for _, path := range s.catalogFiles() {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(path)), data, 0o600); err != nil {
			t.Fatalf("write the backup of %s: %v", path, err)
		}
	}
	return dir
}

// restoreCatalog puts the backup back over the forged file: the side files
// the forgery left are removed, the copied ones come back.
func (s *stack) restoreCatalog(t *testing.T, dir string) {
	t.Helper()
	for _, path := range s.catalogFiles() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", path, err)
		}
		data, err := os.ReadFile(filepath.Join(dir, filepath.Base(path)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read the backup of %s: %v", path, err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("restore %s: %v", path, err)
		}
	}
}

// appendSealed appends e to the audit log of the catalog at path as a forger
// with write access does: sealed with audit.Seal over the file's own head,
// inserted with plain SQL, the generation moved so a running Store reloads.
// It returns the entry's seq.
func appendSealed(t *testing.T, path string, e audit.Entry) int64 {
	t.Helper()
	db, err := sql.Open(sqliteDriver, path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT ` + auditColumns + ` FROM audit_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}
	var prev audit.Entry
	for rows.Next() {
		var cur audit.Entry
		if err := rows.Scan(&cur.Seq, &cur.TS, &cur.Actor, &cur.ActorType, &cur.Event, &cur.Subject, &cur.BeforeHash, &cur.AfterHash, &cur.Detail, &cur.PrevHash, &cur.Hash); err != nil {
			t.Fatalf("scan an audit row: %v", err)
		}
		prev = cur
	}
	_ = rows.Close()
	e.Seq, e.TS = prev.Seq+1, time.Now().UTC().Format(catalogTimeLayout)
	sealed, err := audit.Seal(prev, e)
	if err != nil {
		t.Fatalf("seal the forged entry: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audit_log (`+auditColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sealed.Seq, sealed.TS, sealed.Actor, sealed.ActorType, sealed.Event, sealed.Subject, sealed.BeforeHash, sealed.AfterHash, sealed.Detail, sealed.PrevHash, sealed.Hash); err != nil {
		t.Fatalf("insert the forged entry: %v", err)
	}
	if _, err := db.Exec(`UPDATE meta SET value = value + 1 WHERE key = 'generation'`); err != nil {
		t.Fatalf("move the generation: %v", err)
	}
	return sealed.Seq
}

// execSQL runs one statement against the catalog at path, the forger's edit
// of a mutable column.
func execSQL(t *testing.T, path, query string, args ...any) {
	t.Helper()
	db, err := sql.Open(sqliteDriver, path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// forgedApproval is a version.approved entry about server/tool approving
// digest by actor, shaped as the catalog writes one from pending_review and
// carrying no signed= token: the first forgery of orchestrator decision 14,
// what a forger without a key appends after the bootstrap.
func forgedApproval(actor, server, tool, digest string) audit.Entry {
	return audit.Entry{Actor: actor, ActorType: actorHuman, Event: "version.approved", Subject: server + "/" + tool, AfterHash: digest,
		Detail: "digest=" + digest + " state=pending_review->enabled last_seen=" + digest + " proposals=0->0"}
}

// forgedRevert is a tool.reverted entry by the crawler about server/tool,
// keeping the approved digest and saying state=disabled->enabled: the second
// forgery of decision 14, the crawl-shaped entry that leaves disabled, which
// rule 6 (lifecycle.CrawlMayMove) refuses.
func forgedRevert(server, tool, digest string) audit.Entry {
	return audit.Entry{Actor: crawler, ActorType: actorSystem, Event: "tool.reverted", Subject: server + "/" + tool, BeforeHash: digest, AfterHash: digest,
		Detail: "digest=" + digest + " state=disabled->enabled last_seen=" + digest + " proposals=0->0"}
}

// startProcessorExpectingExit starts one server's processor with the given
// trust root and waits for it to exit instead of to listen: the open-time
// walk must refuse the file. It returns the exit code and both streams.
func (s *stack) startProcessorExpectingExit(t *testing.T, name, root string) (int, string) {
	t.Helper()
	p := s.spawn(t, "processor-"+name, nil, s.h.toolwarrant, s.serveArgs(name, root)...)
	select {
	case <-p.done:
	case <-time.After(portWait):
		t.Fatalf("%s is still running %s after its start; the open-time walk should have refused the file\nstdout:\n%s\nstderr:\n%s", p.name, portWait, p.output(p.stdout), p.output(p.stderr))
	}
	return p.exitCode(), p.output(p.stdout) + p.output(p.stderr)
}

// writeLabFile writes data owner-only under workdir/ssh and returns the path.
func (s *stack) writeLabFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(s.h.workdir, sshDirName, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// fieldAfter returns the word that follows marker in text, or "".
func fieldAfter(text, marker string) string {
	_, rest, ok := strings.Cut(text, marker)
	if !ok {
		return ""
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
