package catalog

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// Each server's processor address lives in the catalog (D14 i). emit used to
// keep a server's processor address stable across re-emits by reading it from
// the file at --out, which is a file anyone who can write that directory can
// write, so a forged address survived the documented CONFIG-EDITED remedy and
// pointed the gateway at a processor of the forger's choosing. The catalog is
// the trusted store: emit records the address it assigned here, one audit
// entry per change, and a re-emit reads it back from here and never from a
// file.

// maxProcessorAddrBytes bounds a processor address: a host name of at most
// 253 bytes, a colon and a port.
const maxProcessorAddrBytes = 260

// errUnchanged is how SetProcessorAddr's transaction says there was nothing
// to write; the caller turns it into a quiet success with no audit entry, so a
// re-emit that assigns every server the address it already has leaves the log
// alone.
var errUnchanged = errors.New("catalog: unchanged")

// SetProcessorAddr records addr as the processor address of the named server
// and writes one server.processor_set audit entry whose detail carries the
// address. A human or a system actor may call it: emit is an operator command,
// but it assigns no approval, and a scheduled re-emit must be able to run
// unattended. The address must be a host:port with a numeric port; an address
// equal to the one recorded is a no-op with no entry. ErrNotFound for an
// unregistered server, ErrInvalid for a bad address or actor.
func (s *Store) SetProcessorAddr(ctx context.Context, server, addr string, by Actor) error {
	if err := validateProcessorAddr(addr); err != nil {
		return err
	}
	actor, err := normalizeActor(by)
	if err != nil {
		return err
	}
	err = s.inTx(ctx, func(t *txn) error {
		srv, err := loadServerRow(ctx, t, server)
		if err != nil {
			return err
		}
		if srv.ProcessorAddr == addr {
			return errUnchanged
		}
		if _, err := t.exec(ctx, `UPDATE servers SET processor_addr = ? WHERE id = ?`, addr, srv.ID); err != nil {
			return fmt.Errorf("catalog: update server: %w", err)
		}
		return t.appendAudit(ctx, actor, evServerProcessorSet, srv.Name, "", "", processorDetail(addr))
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

// validateProcessorAddr accepts host:port where the host is letters, digits,
// dots, hyphens or a bracketed IPv6 literal and the port is 1 to 65535. The
// value lands in an audit detail as one key=value token and in the server
// listing, so it may hold no space, quote or control character; the emitter
// applies its own stricter rules before it ever calls SetProcessorAddr.
func validateProcessorAddr(addr string) error {
	if addr == "" || len(addr) > maxProcessorAddrBytes {
		return invalidf("processor address must be 1 to %d bytes", maxProcessorAddrBytes)
	}
	for i := 0; i < len(addr); i++ {
		if c := addr[i]; !isLowerAlnum(c) && (c < 'A' || c > 'Z') && c != '.' && c != '-' && c != ':' && c != '[' && c != ']' {
			return invalidf("processor address contains a character that is not allowed (byte 0x%02x)", c)
		}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return invalidf("processor address %s must be host:port", quote(addr))
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > maxPort {
		return invalidf("processor address %s has a bad port", quote(addr))
	}
	return nil
}
