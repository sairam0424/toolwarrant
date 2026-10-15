package signing

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// MaxKeyLineBytes bounds one authorized_keys line: an RSA-4096 line is
	// about 740 bytes.
	MaxKeyLineBytes = 4 << 10
	// skPrefix marks the FIDO2 key types, whose signing asks for a touch.
	skPrefix = "sk-"
	// keyAlgoDSA is the ssh-dss type name, refused by name; x/crypto exports
	// it only under a deprecated identifier.
	keyAlgoDSA = "ssh-dss"
	// acceptedKeyTypes names the closed set as an error states it.
	acceptedKeyTypes = "ssh-ed25519, sk-ssh-ed25519@openssh.com, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, sk-ecdsa-sha2-nistp256@openssh.com and ssh-rsa of at least 3072 bits"
)

var (
	// ErrKeyPolicy is returned for a key toolwarrant does not accept: ssh-dss,
	// RSA below MinRSABits, a certificate or an unknown type.
	ErrKeyPolicy = errors.New("signing: key is not one toolwarrant accepts")
	// ErrKeyLine is returned for a key line that is not exactly `type base64`.
	ErrKeyLine = errors.New("signing: key line is not exactly `type base64`")
)

// CheckKeyPolicy refuses the key types the library would sign and verify with
// but toolwarrant does not accept (finding 3): ssh-dss, ssh-rsa below
// MinRSABits, certificates and anything outside the closed set. It runs on
// every key before signing, before verifying and, through internal/trust, on
// every key a list names.
func CheckKeyPolicy(pub ssh.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: no key", ErrKeyPolicy)
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		bits, err := rsaBits(pub)
		if err != nil {
			return err
		}
		if bits < MinRSABits {
			return fmt.Errorf("%w: ssh-rsa key of %d bits is below %d", ErrKeyPolicy, bits, MinRSABits)
		}
		return nil
	case keyAlgoDSA:
		return fmt.Errorf("%w: ssh-dss keys are refused", ErrKeyPolicy)
	}
	return fmt.Errorf("%w: key type %s is not one of %s", ErrKeyPolicy, strconv.Quote(pub.Type()), acceptedKeyTypes)
}

// rsaBits reads the modulus size of an ssh-rsa key. A key an agent lists
// exposes only its wire form, so one that is not an ssh.CryptoPublicKey is
// parsed from its own bytes first.
func rsaBits(pub ssh.PublicKey) (int, error) {
	cp, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		parsed, err := ssh.ParsePublicKey(pub.Marshal())
		if err != nil {
			return 0, fmt.Errorf("%w: ssh-rsa key does not parse: %v", ErrKeyPolicy, err)
		}
		if cp, ok = parsed.(ssh.CryptoPublicKey); !ok {
			return 0, fmt.Errorf("%w: ssh-rsa key exposes no modulus", ErrKeyPolicy)
		}
	}
	rk, ok := cp.CryptoPublicKey().(*rsa.PublicKey)
	if !ok || rk.N == nil {
		return 0, fmt.Errorf("%w: ssh-rsa key exposes no modulus", ErrKeyPolicy)
	}
	return rk.N.BitLen(), nil
}

// NeedsTouch reports whether signing with pub asks for a physical touch: the
// FIDO2 (sk-) types, which only an agent can hold.
func NeedsTouch(pub ssh.PublicKey) bool {
	return pub != nil && strings.HasPrefix(pub.Type(), skPrefix)
}

// ParseAuthorizedKey reads exactly one key line as a trust list stores it:
// `type base64`, one space, no options, no comment, no surrounding space, the
// base64 strict and the line equal to MarshalKey of the key it encodes.
// x/crypto's ParseAuthorizedKey tolerates all of those and skips lines it
// cannot read; a stored key must have one spelling. The shape is checked
// here; CheckKeyPolicy decides whether the key is accepted.
func ParseAuthorizedKey(line string) (ssh.PublicKey, error) {
	if len(line) > MaxKeyLineBytes {
		return nil, fmt.Errorf("%w: %d bytes, more than %d", ErrKeyLine, len(line), MaxKeyLineBytes)
	}
	typ, b64, ok := strings.Cut(line, " ")
	if !ok || typ == "" || b64 == "" || strings.ContainsAny(b64, " \t\r\n") {
		return nil, fmt.Errorf("%w: one space between the type and the base64, no options and no comment", ErrKeyLine)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: the key is not strict base64", ErrKeyLine)
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyLine, err)
	}
	if pub.Type() != typ {
		return nil, fmt.Errorf("%w: declared type %s, encoded type %s", ErrKeyLine, strconv.Quote(typ), strconv.Quote(pub.Type()))
	}
	if MarshalKey(pub) != line {
		return nil, fmt.Errorf("%w: the line is not the canonical spelling of its key", ErrKeyLine)
	}
	return pub, nil
}

// MarshalKey renders a public key as the one line a trust list stores and
// ParseAuthorizedKey reads back: `type base64`, no comment, no newline.
func MarshalKey(pub ssh.PublicKey) string {
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
}
