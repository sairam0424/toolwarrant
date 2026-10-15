package trust

import (
	"strings"

	"github.com/sairam0424/toolwarrant/internal/signing"
)

// allowedSignersOption is the option every rendered line carries: the key may
// sign under toolwarrant's two namespaces and nothing else, so an auditor's
// `ssh-keygen -Y verify` refuses a git or export signature by the file alone.
// The spelling is ssh-keygen(1) ALLOWED SIGNERS: namespaces="a,b".
const allowedSignersOption = `namespaces="` + string(signing.NamespaceDecision) + "," + string(signing.NamespaceTrust) + `"`

// AllowedSigners renders a Record as the allowed_signers file stock
// `ssh-keygen -Y verify -f FILE -I NAME -n NAMESPACE` reads: one line per
// key, `NAME namespaces="decision@toolwarrant.invalid,trust@toolwarrant.invalid" KEYTYPE BASE64`,
// in list order, each ending in a newline. The key is the stored line itself,
// so the file holds exactly the public keys the chain holds. A Record that
// Validate did not produce renders nothing and is an error.
func AllowedSigners(r Record) ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b strings.Builder
	for _, op := range r.Signers {
		b.WriteString(op.Name)
		b.WriteByte(' ')
		b.WriteString(allowedSignersOption)
		b.WriteByte(' ')
		b.WriteString(op.Key)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
