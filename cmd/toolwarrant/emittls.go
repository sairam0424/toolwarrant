package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// TLS on the gateway's side of the processor link (D19): the repeatable
// --processor-tls flag puts the processors[].policies.backendTLS block on one
// server's processor entry. The block names three files on the gateway host
// (the client certificate and key the gateway presents, the root it verifies
// the processor against) and the DNS name of the processor's certificate.
// None of it is stored in the catalog: the paths are the gateway host's, which
// the catalog cannot anchor, and persisting them would be schema v7 with a
// migration, so the flag is given on every emit, as --secret-env is, and an
// emit without it writes an entry the gateway dials in plaintext, which a
// processor started with --tls-cert refuses in the handshake (fail closed).
const (
	flagProcessorTLS = "--processor-tls"
	// processorTLSGrammar is the shape of one value: the server name, then
	// the four fields in any order, comma-separated, each exactly once. A path
	// cannot carry a comma.
	processorTLSGrammar = "NAME=cert=PATH,key=PATH,root=PATH,hostname=NAME"
	tlsFieldSep         = ","
	tlsKeyValueSep      = "="
	tlsFieldCount       = 4
	// tlsServePlaceholders are the serve flags the printed command carries for
	// a server whose entry has the block: the processor's certificate and key
	// and the authority that signed the gateway's client certificate live on
	// the processor's host, so emit prints names to fill in, not paths.
	tlsServePlaceholders = " --tls-cert PROCESSOR_CERT --tls-key PROCESSOR_KEY --tls-client-ca GATEWAY_CA"
)

// processorTLSFlags is the repeatable --processor-tls flag: one block per
// server name.
type processorTLSFlags map[string]emit.ProcessorTLS

func (p processorTLSFlags) String() string {
	parts := make([]string, 0, len(p))
	for name, t := range p {
		parts = append(parts, name+tlsKeyValueSep+formatProcessorTLS(t))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// formatProcessorTLS renders a block in the flag's grammar, fields in the
// documented order.
func formatProcessorTLS(t emit.ProcessorTLS) string {
	return strings.Join([]string{"cert=" + t.Cert, "key=" + t.Key, "root=" + t.Root, "hostname=" + t.Hostname}, tlsFieldSep)
}

// Set records one block. The flag package reports the error with the raw
// value, and the dispatcher escapes the whole message once before printing,
// so nothing is escaped here; the message names the grammar, since the fix is
// the flag.
func (p processorTLSFlags) Set(v string) error {
	name, spec, ok := strings.Cut(v, tlsKeyValueSep)
	if !ok || name == "" || spec == "" {
		return errors.New("want " + processorTLSGrammar)
	}
	if _, dup := p[name]; dup {
		return errors.New("server given twice")
	}
	t, err := parseProcessorTLS(spec)
	if err != nil {
		return err
	}
	p[name] = t
	return nil
}

// parseProcessorTLS reads the four comma-separated fields after the server
// name: each key once, no key missing, no value empty, nothing else.
func parseProcessorTLS(spec string) (emit.ProcessorTLS, error) {
	var t emit.ProcessorTLS
	fields := map[string]*string{"cert": &t.Cert, "key": &t.Key, "root": &t.Root, "hostname": &t.Hostname}
	parts := strings.Split(spec, tlsFieldSep)
	if len(parts) != tlsFieldCount {
		return t, fmt.Errorf("want %d fields %s, got %d", tlsFieldCount, processorTLSGrammar, len(parts))
	}
	for _, part := range parts {
		key, value, ok := strings.Cut(part, tlsKeyValueSep)
		dst, known := fields[key]
		switch {
		case !ok || !known:
			return t, fmt.Errorf("unknown field %s: want %s", part, processorTLSGrammar)
		case value == "":
			return t, fmt.Errorf("field %s is empty: want %s", key, processorTLSGrammar)
		case *dst != "":
			return t, fmt.Errorf("field %s given twice", key)
		}
		*dst = value
	}
	return t, nil
}

// attachProcessorTLS returns the plans with each named server's block attached.
// A name that is no server of the catalog is a usage error, as it is for
// --processor: a flag that names nothing would silently leave that link in
// plaintext. The plans are copied; the caller's slice is not written to.
func attachProcessorTLS(c *command, plans []emitPlan, flags processorTLSFlags) ([]emitPlan, error) {
	out := make([]emitPlan, 0, len(plans))
	known := map[string]bool{}
	for _, p := range plans {
		known[p.name] = true
		if t, ok := flags[p.name]; ok {
			block := t
			p.tls = &block
		}
		out = append(out, p)
	}
	for name := range flags {
		if !known[name] {
			return nil, &usageError{msg: fmt.Sprintf("%s names unknown server %s", flagProcessorTLS, textdiff.Escape(name)), cmd: c}
		}
	}
	return out, nil
}
