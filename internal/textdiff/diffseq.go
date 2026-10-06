package textdiff

// The limits below bound the cost of a diff. A diff of two huge, unrelated
// inputs would otherwise take quadratic time or memory, and the inputs come
// from upstream servers. Past a limit the differing block is reported as one
// whole-block replace: still correct and complete, just not minimal.
const (
	// maxDiffItems is the most lines (or words) on either side of the
	// differing block, after the common start and end are trimmed off.
	maxDiffItems = 20000
	// maxEditDistance is the most inserts plus deletes the minimal search
	// will look for. The search keeps O(distance squared) state.
	maxEditDistance = 2000
)

type editKind uint8

const (
	kindEqual editKind = iota
	kindDelete
	kindInsert
)

// edit is one step of a diff. For kindEqual and kindDelete, aIdx is the index
// in the first sequence; for kindEqual and kindInsert, bIdx is the index in the
// second. The index that does not apply to a step is only a position marker
// and must not be used to read an item.
type edit struct {
	kind editKind
	aIdx int
	bIdx int
}

// diffSeq returns a deterministic diff that turns a into b. Equal steps form a
// longest common subsequence whenever the inputs are within the limits above.
// Within each run of changes all deletes come before all inserts, the way
// unified diffs are conventionally shown.
func diffSeq[T comparable](a, b []T) []edit {
	prefix := commonPrefix(a, b)
	suffix := commonSuffix(a[prefix:], b[prefix:])
	midA := a[prefix : len(a)-suffix]
	midB := b[prefix : len(b)-suffix]

	mid, ok := []edit(nil), false
	if len(midA) > 0 && len(midB) > 0 && len(midA) <= maxDiffItems && len(midB) <= maxDiffItems {
		mid, ok = myers(midA, midB)
	}
	if !ok {
		mid = replaceBlock(len(midA), len(midB))
	}

	out := make([]edit, 0, prefix+len(mid)+suffix)
	for i := 0; i < prefix; i++ {
		out = append(out, edit{kindEqual, i, i})
	}
	for _, e := range mid {
		out = append(out, edit{e.kind, e.aIdx + prefix, e.bIdx + prefix})
	}
	for j := 0; j < suffix; j++ {
		out = append(out, edit{kindEqual, len(a) - suffix + j, len(b) - suffix + j})
	}
	return deletesFirst(out)
}

func commonPrefix[T comparable](a, b []T) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

func commonSuffix[T comparable](a, b []T) int {
	n := 0
	for n < len(a) && n < len(b) && a[len(a)-1-n] == b[len(b)-1-n] {
		n++
	}
	return n
}

// replaceBlock deletes all of the first block and inserts all of the second.
func replaceBlock(aLen, bLen int) []edit {
	out := make([]edit, 0, aLen+bLen)
	for i := 0; i < aLen; i++ {
		out = append(out, edit{kindDelete, i, 0})
	}
	for j := 0; j < bLen; j++ {
		out = append(out, edit{kindInsert, aLen, j})
	}
	return out
}

// deletesFirst reorders every run of non-equal steps so deletes precede
// inserts, keeping the order inside each group. It returns a new slice.
func deletesFirst(in []edit) []edit {
	out := make([]edit, 0, len(in))
	for i := 0; i < len(in); {
		if in[i].kind == kindEqual {
			out = append(out, in[i])
			i++
			continue
		}
		j := i
		for j < len(in) && in[j].kind != kindEqual {
			j++
		}
		for _, e := range in[i:j] {
			if e.kind == kindDelete {
				out = append(out, e)
			}
		}
		for _, e := range in[i:j] {
			if e.kind == kindInsert {
				out = append(out, e)
			}
		}
		i = j
	}
	return out
}

// myers computes a shortest edit script with Myers' O(ND) algorithm. It
// returns false when the script would need more than maxEditDistance changes.
// Ties are broken the same way every time, so the output is reproducible.
func myers[T comparable](a, b []T) ([]edit, bool) {
	n, m := len(a), len(b)
	limit := min(n+m, maxEditDistance)
	// trace[d][i] is the furthest x reached on diagonal k = 2*i-d after d edits.
	trace := make([][]int32, 0, 16)
	for d := 0; d <= limit; d++ {
		cur := make([]int32, d+1)
		for i := 0; i <= d; i++ {
			x := startX(trace, d, i)
			y := x - (2*i - d)
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			cur[i] = int32(x)
			if x == n && y == m {
				trace = append(trace, cur)
				return backtrack(trace, n, m), true
			}
		}
		trace = append(trace, cur)
	}
	return nil, false
}

// startX picks the better of the two neighbouring diagonals from round d-1
// (moving down is an insert, moving right is a delete) and returns the x
// where the snake on diagonal index i of round d begins.
func startX(trace [][]int32, d, i int) int {
	if d == 0 {
		return 0
	}
	prev := trace[d-1]
	if i == 0 || (i != d && prev[i-1] < prev[i]) {
		return int(prev[i])
	}
	return int(prev[i-1]) + 1
}

// backtrack walks the trace from (n, m) back to the start and returns the
// edit script in forward order.
func backtrack(trace [][]int32, n, m int) []edit {
	x, y := n, m
	rev := make([]edit, 0, n+m)
	for d := len(trace) - 1; d > 0; d-- {
		prev := trace[d-1]
		i := ((x - y) + d) / 2
		insert := i == 0 || (i != d && prev[i-1] < prev[i])
		pi := i - 1
		if insert {
			pi = i
		}
		px := int(prev[pi])
		py := px - (2*pi - (d - 1))
		mx, my := px+1, py
		if insert {
			mx, my = px, py+1
		}
		for x > mx && y > my {
			x--
			y--
			rev = append(rev, edit{kindEqual, x, y})
		}
		if insert {
			rev = append(rev, edit{kindInsert, px, py})
		} else {
			rev = append(rev, edit{kindDelete, px, py})
		}
		x, y = px, py
	}
	for x > 0 && y > 0 {
		x--
		y--
		rev = append(rev, edit{kindEqual, x, y})
	}
	out := make([]edit, len(rev))
	for i, e := range rev {
		out[len(rev)-1-i] = e
	}
	return out
}
