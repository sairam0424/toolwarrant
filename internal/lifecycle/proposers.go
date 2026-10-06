package lifecycle

import (
	"encoding/binary"
	"slices"
	"strings"
)

// Proposers is the append-only list of every principal whose crawl ever
// proposed one version, oldest first.
//
// Why a list and not only the single ProposedBy: the two-person rule says the
// approver must differ from whoever introduced the bytes. If a re-proposal
// could rename the proposer, the person who first crawled a definition could
// approve it after any colleague's crawl saw it again. Every proposer is kept
// so approve can refuse all of them.
//
// Why a value type and not a slice: Version must stay comparable with ==, the
// catalog compares versions that way to find what changed, and a value cannot
// be mutated behind a clone's back. Add returns a new value; the receiver is
// never changed.
type Proposers struct {
	// packed holds every name as a uvarint length followed by the bytes, so any
	// string, including one containing separators or NULs, round-trips exactly
	// and two equal lists are equal strings.
	packed string
}

// ProposersOf builds the list in order, skipping empty and repeated names.
func ProposersOf(names ...string) Proposers {
	var p Proposers
	for _, n := range names {
		p = p.Add(n)
	}
	return p
}

// Add returns the list with name appended, or the receiver unchanged when the
// name is empty or already present: a proposer is recorded once.
func (p Proposers) Add(name string) Proposers {
	if name == "" || p.Contains(name) {
		return p
	}
	var size [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(size[:], uint64(len(name)))
	return Proposers{packed: p.packed + string(size[:n]) + name}
}

// All returns every proposer, oldest first; nil when there is none. The
// returned slice is fresh, so callers cannot change the list.
func (p Proposers) All() []string {
	var out []string
	rest := p.packed
	for rest != "" {
		size, n := binary.Uvarint([]byte(rest[:min(len(rest), binary.MaxVarintLen64)]))
		if n <= 0 || size > uint64(len(rest)-n) {
			// Unreachable through Add, which is the only writer; stop rather
			// than invent names from a prefix that is not a complete entry.
			break
		}
		out = append(out, rest[n:n+int(size)])
		rest = rest[n+int(size):]
	}
	return out
}

// First returns the original proposer, or "" for an empty list.
func (p Proposers) First() string {
	all := p.All()
	if len(all) == 0 {
		return ""
	}
	return all[0]
}

// Len returns how many principals proposed the version.
func (p Proposers) Len() int { return len(p.All()) }

// Contains reports whether name is one of the proposers.
func (p Proposers) Contains(name string) bool { return slices.Contains(p.All(), name) }

// String joins the proposers with commas; it exists so test output and logs
// show names rather than the packed encoding.
func (p Proposers) String() string { return strings.Join(p.All(), ",") }

// proposersOf returns v's proposers, falling back to ProposedBy for a version
// that was stored before the list existed, so that it is still protected.
func proposersOf(v Version) Proposers {
	if v.Proposers.Len() > 0 {
		return v.Proposers
	}
	return ProposersOf(v.ProposedBy)
}

// isProposer reports whether actor ever proposed v. ProposedBy is consulted as
// well as the list for the same reason as in proposersOf.
func isProposer(v Version, actor string) bool {
	return actor == v.ProposedBy || v.Proposers.Contains(actor)
}
