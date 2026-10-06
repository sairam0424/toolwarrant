package emit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// The hash line seals the body. Verify accepts only the exact form seal
// writes: the constant header, this prefix, 64 lowercase hex digits and a
// newline. Anything looser would let a reformatted copy pass as untouched.
const (
	hashLinePrefix = "# toolwarrant-sha256: "
	hashHexLen     = sha256.Size * 2
)

// seal prefixes body with the generated-file header and the hash line and
// returns the whole file plus the digest it recorded.
func seal(body []byte) ([]byte, string) {
	digest := bodyDigest(body)
	var b bytes.Buffer
	b.Grow(len(generatedHeader) + len(hashLinePrefix) + hashHexLen + 1 + len(body))
	b.WriteString(generatedHeader)
	b.WriteString(hashLinePrefix)
	b.WriteString(digest)
	b.WriteByte('\n')
	b.Write(body)
	return b.Bytes(), digest
}

// bodyDigest is the lowercase hex SHA-256 of body.
func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Verify reports whether file is byte for byte what AgentGateway wrote: the
// exact header, the hash line, and a body whose SHA-256 equals the recorded
// digest. bodyHash is the digest of the body actually present so a canary can
// log it next to the one it expected; it is empty when the header is missing
// or malformed. agentgateway reloads an edited file with one log line and a
// route whose processor entry was removed fails open for every new session,
// so a false result is a serving incident, not a formatting problem.
func Verify(file []byte) (bodyHash string, ok bool) {
	rest, found := bytes.CutPrefix(file, []byte(generatedHeader+hashLinePrefix))
	if !found || len(rest) <= hashHexLen || rest[hashHexLen] != '\n' {
		return "", false
	}
	recorded := string(rest[:hashHexLen])
	digest := bodyDigest(rest[hashHexLen+1:])
	return digest, digest == recorded
}
