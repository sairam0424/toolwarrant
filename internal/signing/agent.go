package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SigningKey is a private key ready to sign one or more records: an SSH
// signer that can choose its algorithm (RSA must sign rsa-sha2-512), whether
// a signature asks for a physical touch, and a Close that drops the agent
// connection or clears the key bytes when the command ends.
type SigningKey interface {
	ssh.AlgorithmSigner
	// NeedsTouch is true for a FIDO2 (sk-) key, so the CLI can say so before
	// the agent waits.
	NeedsTouch() bool
	// Close releases the key; the key must not be used after it.
	Close() error
}

const (
	// sharedBits are the permission bits that give group or others any
	// access: the export key's rule, applied to sockets and key files.
	sharedBits fs.FileMode = 0o077
	// unixNetwork is the one network an agent is dialled on.
	unixNetwork = "unix"
	// deadlineSlack is how far after the context's deadline the connection's
	// own deadline sits, so the context fails first and a failed exchange
	// carries the context's error; the connection deadline is the backstop.
	deadlineSlack = 50 * time.Millisecond
	// deadlineGrace is how long a failed exchange waits for a context that is
	// about to end before reporting the connection's error instead.
	deadlineGrace = 100 * time.Millisecond
)

var (
	// ErrAgentSocket is returned when SSH_AUTH_SOCK does not name a unix
	// socket this user alone can reach: unset, too long, a link, a regular
	// file, another user's, or shared without a private directory around it.
	ErrAgentSocket = errors.New("signing: SSH_AUTH_SOCK does not name a private ssh-agent socket")
	// ErrAgent is returned when the agent cannot be dialled or does not
	// answer within AgentTimeout or the caller's context.
	ErrAgent = errors.New("signing: ssh-agent at SSH_AUTH_SOCK")
	// ErrKeyNotInAgent is returned when the agent holds no key with the
	// requested fingerprint, which follows the message.
	ErrKeyNotInAgent = errors.New("signing: ssh-agent at SSH_AUTH_SOCK does not hold the key")
)

// Agent is an open connection to ssh-agent with its key list read once at
// open. It is not safe for concurrent use; a command opens one, takes one
// key and closes it.
type Agent struct {
	conn    net.Conn
	signers []ssh.Signer
	closed  bool
}

// OpenAgent checks sock under the socket rules, dials it within AgentTimeout
// and the context, and lists its keys within the same bound. The socket must
// come from SSH_AUTH_SOCK; the package never reads the environment itself.
func OpenAgent(ctx context.Context, sock string) (*Agent, error) {
	if err := checkSocket(sock); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: AgentTimeout}
	conn, err := dialer.DialContext(ctx, unixNetwork, sock)
	if err != nil {
		return nil, fmt.Errorf("%w: dial: %v", ErrAgent, err)
	}
	start := time.Now()
	release := bindConn(ctx, conn, AgentTimeout)
	signers, err := agent.NewClient(conn).Signers()
	release()
	if err != nil {
		_ = conn.Close()
		if cerr := deadlineError(ctx, err); cerr != nil {
			return nil, fmt.Errorf("%w: list keys: %w (%v)", ErrAgent, cerr, err)
		}
		if time.Since(start) >= AgentTimeout {
			return nil, fmt.Errorf("%w: list keys: no answer within %v: %w (%v)", ErrAgent, AgentTimeout, context.DeadlineExceeded, err)
		}
		return nil, fmt.Errorf("%w: list keys: %v", ErrAgent, err)
	}
	return &Agent{conn: conn, signers: signers}, nil
}

// checkSocket is the rule for SSH_AUTH_SOCK: set, shorter than
// MaxSocketPathBytes, a unix socket by Lstat (no link followed), owned by this
// uid, and either with no group or other bits (OpenSSH's ssh-agent makes it
// 0600) or inside a directory of this uid with no group or other bits
// (launchd's agent makes a 0666 socket in a 0700 directory). A socket anyone
// else can reach is refused before it is dialled.
func checkSocket(sock string) error {
	if sock == "" {
		return fmt.Errorf("%w: it is not set", ErrAgentSocket)
	}
	if len(sock) >= MaxSocketPathBytes {
		return fmt.Errorf("%w: the path is %d bytes, which must be under %d", ErrAgentSocket, len(sock), MaxSocketPathBytes)
	}
	fi, err := os.Lstat(sock)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentSocket, err)
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%w: not a unix socket (a symbolic link, a regular file or a directory is refused)", ErrAgentSocket)
	}
	if err := ownedByThisUser(fi, "the socket"); err != nil {
		return err
	}
	if fi.Mode().Perm()&sharedBits == 0 {
		return nil
	}
	dir := filepath.Dir(sock)
	dfi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentSocket, err)
	}
	if !dfi.Mode().IsDir() || dfi.Mode().Perm()&sharedBits != 0 {
		return fmt.Errorf("%w: the socket has mode %04o and its directory is not a private (0700) directory, so other users can reach it", ErrAgentSocket, fi.Mode().Perm())
	}
	return ownedByThisUser(dfi, "the socket's directory")
}

// ownedByThisUser refuses an entry another uid owns.
func ownedByThisUser(fi fs.FileInfo, what string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot read the owner of %s", ErrAgentSocket, what)
	}
	if uid := os.Getuid(); st.Uid != uint32(uid) {
		return fmt.Errorf("%w: %s is owned by uid %d, not this user (%d)", ErrAgentSocket, what, st.Uid, uid)
	}
	return nil
}

// bindConn bounds the I/O on conn by the context, and by max when max is
// positive, until the returned release is called. A context that ends fails
// the pending exchange at once by moving the deadline into the past; the
// connection's own deadline sits deadlineSlack after the context's as the
// backstop. The connection is then out of step with the agent and must be
// closed.
func bindConn(ctx context.Context, conn net.Conn, max time.Duration) (release func()) {
	var deadline time.Time
	if max > 0 {
		deadline = time.Now().Add(max)
	}
	if dl, ok := ctx.Deadline(); ok {
		if dl = dl.Add(deadlineSlack); deadline.IsZero() || dl.Before(deadline) {
			deadline = dl
		}
	}
	_ = conn.SetDeadline(deadline)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Unix(1, 0))
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-done
		_ = conn.SetDeadline(time.Time{})
	}
}

// deadlineError names the context's error for a failed agent exchange, or nil
// when the context did not end. The agent client formats the connection's
// error with %v, so the timeout cannot be seen through it; instead, when the
// context can end, the exchange's failure waits up to deadlineGrace for it to
// do so, which it does within microseconds when the failure was the deadline
// bindConn set from it.
func deadlineError(ctx context.Context, err error) error {
	if err == nil || ctx.Done() == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	timer := time.NewTimer(deadlineGrace)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SignerFor returns the agent's key whose public half is pub, after the key
// policy. The agent is asked to sign with that key only, and a Sign through
// it is bounded by the caller's context.
func (a *Agent) SignerFor(pub ssh.PublicKey) (SigningKey, error) {
	if err := CheckKeyPolicy(pub); err != nil {
		return nil, err
	}
	want := pub.Marshal()
	for _, s := range a.signers {
		if !bytes.Equal(s.PublicKey().Marshal(), want) {
			continue
		}
		as, ok := s.(ssh.AlgorithmSigner)
		if !ok {
			return nil, fmt.Errorf("%w: the agent's signer for %s cannot choose a signature algorithm", ErrAgent, Fingerprint(pub))
		}
		return &agentKey{AlgorithmSigner: as, agent: a}, nil
	}
	return nil, fmt.Errorf("%w %s", ErrKeyNotInAgent, Fingerprint(pub))
}

// Close closes the connection; a second Close does nothing.
func (a *Agent) Close() error {
	if a.closed {
		return nil
	}
	a.closed = true
	return a.conn.Close()
}

// agentKey is a key the agent holds; signing is one request on the agent's
// connection, bounded by the context Sign binds.
type agentKey struct {
	ssh.AlgorithmSigner
	agent *Agent
}

// NeedsTouch reports whether the key is a FIDO2 key.
func (k *agentKey) NeedsTouch() bool { return NeedsTouch(k.PublicKey()) }

// Close closes the agent connection the key signs through.
func (k *agentKey) Close() error { return k.agent.Close() }

// bindContext bounds the agent exchange by the caller's context alone: a
// touch may legitimately take as long as the CLI's --sign-timeout allows.
func (k *agentKey) bindContext(ctx context.Context) func() {
	return bindConn(ctx, k.agent.conn, 0)
}
