package textdiff

// changedValue is one string value that differs between the two documents. A
// value present on one side only has the empty string on the other.
type changedValue struct {
	path *pathNode
	from string
	to   string
}

// compareAll walks the two decoded documents together and lists every string
// value that differs, in document order (keys sorted, arrays by index). Object
// keys are not values and are not compared as such; the diff shows them. The
// second list holds the key swaps: for every object, each key present only in
// the new document that reads the same (equal skeletons) as a key present only
// in the old one, recorded with the new key's path, the old key as from and
// the new key as to; the diff shows both keys but cannot show that they look
// alike. Walking both trees at once needs no map keyed by path text, so the
// paths of the values that are equal, which is nearly all of them, are never
// rendered.
func compareAll(from, to any) (values, keySwaps []changedValue) {
	c := &comparer{}
	c.compare(from, to, rootNode())
	return c.out, c.keySwaps
}

type comparer struct {
	out      []changedValue
	keySwaps []changedValue
}

func (c *comparer) compare(from, to any, node *pathNode) {
	switch f := from.(type) {
	case map[string]any:
		if t, ok := to.(map[string]any); ok {
			c.compareObjects(f, t, node)
			return
		}
	case []any:
		if t, ok := to.([]any); ok {
			c.compareArrays(f, t, node)
			return
		}
	case string:
		if t, ok := to.(string); ok {
			c.add(node, f, t)
			return
		}
	}
	// Different shapes: every string on either side counts as removed or added.
	c.oneSided(from, node, true)
	c.oneSided(to, node, false)
}

func (c *comparer) compareObjects(from, to map[string]any, node *pathNode) {
	var removed, added []string
	for _, k := range mergedKeys(from, to) {
		fv, inFrom := from[k]
		tv, inTo := to[k]
		child := node.child(k)
		switch {
		case inFrom && inTo:
			c.compare(fv, tv, child)
		case inFrom:
			removed = append(removed, k)
			c.oneSided(fv, child, true)
		default:
			added = append(added, k)
			c.oneSided(tv, child, false)
		}
	}
	c.pairKeys(node, removed, added)
}

// pairKeys records every added key whose skeleton equals a removed key's. The
// removed keys' skeletons are computed once into a map, so two thousand
// renamed properties cost two thousand skeletons, not four million.
func (c *comparer) pairKeys(node *pathNode, removed, added []string) {
	if len(removed) == 0 || len(added) == 0 {
		return
	}
	bySkeleton := map[string][]string{}
	for _, k := range removed {
		sk := Skeleton(k)
		bySkeleton[sk] = append(bySkeleton[sk], k)
	}
	for _, k := range added {
		for _, old := range bySkeleton[Skeleton(k)] {
			c.keySwaps = append(c.keySwaps, changedValue{path: node.child(k), from: old, to: k})
		}
	}
}

func (c *comparer) compareArrays(from, to []any, node *pathNode) {
	for i := 0; i < max(len(from), len(to)); i++ {
		child := node.element(i)
		switch {
		case i < len(from) && i < len(to):
			c.compare(from[i], to[i], child)
		case i < len(from):
			c.oneSided(from[i], child, true)
		default:
			c.oneSided(to[i], child, false)
		}
	}
}

// oneSided records every string value under v as removed (or added).
func (c *comparer) oneSided(v any, node *pathNode, removed bool) {
	walkStrings(v, node, func(e stringEntry) {
		if e.isKey {
			return
		}
		if removed {
			c.add(e.node, e.value, "")
		} else {
			c.add(e.node, "", e.value)
		}
	})
}

// add records a change unless both sides are the same text.
func (c *comparer) add(node *pathNode, from, to string) {
	if from != to {
		c.out = append(c.out, changedValue{path: node, from: from, to: to})
	}
}

// mergedKeys returns the union of both key sets in byte order.
func mergedKeys(from, to map[string]any) []string {
	a, b := sortedKeys(from), sortedKeys(to)
	out := make([]string, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		switch {
		case a[0] < b[0]:
			out = append(out, a[0])
			a = a[1:]
		case a[0] > b[0]:
			out = append(out, b[0])
			b = b[1:]
		default:
			out = append(out, a[0])
			a, b = a[1:], b[1:]
		}
	}
	out = append(out, a...)
	return append(out, b...)
}
