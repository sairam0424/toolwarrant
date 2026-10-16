package main

import (
	"fmt"
	"strings"
)

// The backendTLS block of a processor entry as the comparison reads and
// compares it (limit L11). agentgateway v1.6.0 dials the processor with TLS
// when the entry carries processors[].policies.backendTLS: cert and key name
// the client certificate the gateway presents, root the bundle it verifies the
// processor's certificate against, hostname the name it verifies and sends as
// SNI. The v1.6.0 schema also accepts insecure, insecureHost, alpn,
// subjectAltNames, keyExchangeGroups and spiffe inside the block, and
// requestHeaderModifier, transformations and backendAuth beside it; emit
// writes none of those, so each is one line of the shape walk (liveshape.go).
// The canary reads the block before emit writes it, so that a file without
// the block compares exactly as before and a live block is never a match the
// comparison could not read. The four values are paths on the gateway host
// and a DNS name, not secrets, so a difference line shows them.

// The lines about a backendTLS block that one side lacks. Without the block
// the gateway dials the processor in plaintext, which is what the block exists
// to end; a block the file does not carry gives the link a trust the operator
// never emitted.
const (
	tlsLiveMissing = "processor backendTLS: the live processor has none while the emitted file carries it; the gateway dials this processor without TLS"
	tlsLiveExtra   = "processor backendTLS: the live processor carries backendTLS the emitted file does not"
	tlsFieldPrefix = "processor backendTLS "
)

// tlsKeys are the backendTLS fields emit writes, in file order. A function,
// so the package holds no mutable slice.
func tlsKeys() []string { return []string{keyTLSCert, keyTLSKey, keyTLSRoot, keyTLSHostname} }

// policyLine reads one indent-10 line of the open policies block of a
// processor: the backendTLS opener, whose fields follow at indent 12, or
// another policy, which emit never writes and whose lines are left unread
// rather than taken for TLS fields. A second backendTLS block is refused: the
// comparison cannot know which one the gateway applies.
func (p *emittedParser) policyLine(line string) error {
	if line != keyBackendTLS {
		p.procSection = procSectionPolicies
		return nil
	}
	if p.proc.tls != nil {
		return fmt.Errorf("the emitted file lists %s twice for processor %s", tlsBlockName, p.proc.host)
	}
	p.procSection, p.proc.tls = procSectionTLS, map[string]string{}
	return nil
}

// tlsLine reads one indent-12 field of the open backendTLS block: a key and a
// quoted scalar, as emit writes cert, key, root and hostname. An unquoted
// value, which is what the schema's insecure: true or a list would be, is one
// emit could not have written and is refused like every other unquoted
// scalar, so the comparison never guesses at it.
func (p *emittedParser) tlsLine(line string) error {
	key, value, _ := strings.Cut(line, keyValueSep)
	v, err := unquoteScalar(value)
	if err != nil {
		return err
	}
	p.proc.tls[key] = v
	return nil
}

// compareProcessorTLS compares the backendTLS block of one processor entry:
// which side has one, then the four fields emit writes, each a difference
// line of its own with both values shown. A nil map is an entry without the
// block; an empty map is an empty block, which the gateway accepts and which
// differs from no block at all.
func compareProcessorTLS(emitted, live map[string]string) []string {
	switch {
	case emitted == nil && live == nil:
		return nil
	case live == nil:
		return []string{tlsLiveMissing}
	case emitted == nil:
		return []string{tlsLiveExtra}
	}
	var diffs []string
	for _, k := range tlsKeys() {
		diffs = appendDiff(diffs, tlsFieldPrefix+k, emitted[k], live[k])
	}
	return diffs
}
