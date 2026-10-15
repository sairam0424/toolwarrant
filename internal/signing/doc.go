// Package signing makes and checks the OpenSSH signatures (PROTOCOL.sshsig)
// that bind a human decision, or the operator trust list, to a person's SSH
// key (D22 (a), the research report L13 findings 1, 2, 3, 7 and 8).
//
// Why sshsig. One primitive covers a key on disk, a key in a local or
// forwarded ssh-agent and a FIDO2 key that asks for a touch, identity stays in
// toolwarrant's own trust list rather than in a certificate authority, and an
// auditor re-verifies a record with stock `ssh-keygen -Y verify`. The envelope
// is github.com/hiddeco/sshsig over golang.org/x/crypto/ssh; every call into
// it goes through Sign and Verify here, so a replacement envelope would touch
// this package only.
//
// Two namespaces. A signature carries its namespace inside the signed
// structure, so a signature made for one purpose fails cryptographically under
// another (finding 2). Decisions are signed under NamespaceDecision and trust
// lists under NamespaceTrust; a git commit signature (`-n git`) or an export
// signature can never be presented as either. The namespace is a Namespace
// constant, never a caller string, and Sign and Verify refuse any value
// outside the closed set, so an empty expected namespace, which the library's
// Verify would accept, cannot be passed.
//
// Sign the bytes, verify before parsing. A payload is the exact RFC 8785 bytes
// MarshalDecision or MarshalTrustList produced once; those bytes are what is
// signed, what the catalog stores and what Verify checks, and only a payload
// whose signature verified is handed to ParseDecision or ParseTrustList, which
// in turn accept exactly those bytes and nothing semantically equal to them
// (finding 7). Every payload carries its own `type` inside the signed bytes,
// so a trust list cannot be read as a decision or the reverse (finding 8).
//
// Keys. The private half lives in ssh-agent (OpenAgent, under the socket
// rules) or in an unencrypted OpenSSH private key file (ReadPrivateKeyFile,
// under the export key's file rules); KeySource picks between the two the way
// `ssh-keygen -Y sign -f` does, from the file's content. CheckKeyPolicy
// refuses ssh-dss and RSA below MinRSABits, which the library does not
// (finding 3). No function here returns or prints private material; the only
// key text an error or a record carries is the SHA256: fingerprint, and the
// public line appears only where the trust list is rendered.
package signing
