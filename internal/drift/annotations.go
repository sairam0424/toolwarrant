package drift

import "strconv"

// hintRule is one boolean annotation hint: the MCP default a host applies when
// the hint is absent, and the value under which a host restricts the tool
// more. Moving away from that value is the loosening threat-model row 3
// describes for annotations; moving towards it is still a change.
type hintRule struct {
	name string
	def  bool
	safe bool
}

// hintRules lists the four hints of MCP revision 2026-07-28 with their
// defaults: readOnlyHint false, destructiveHint true, openWorldHint true,
// idempotentHint false. A fresh slice is returned so that no package-level
// state exists.
func hintRules() []hintRule {
	return []hintRule{
		{name: "readOnlyHint", def: false, safe: true},
		{name: "destructiveHint", def: true, safe: false},
		{name: "openWorldHint", def: true, safe: false},
		{name: "idempotentHint", def: false, safe: true},
	}
}

// effective returns the hint as a host reads it: the boolean when the member
// is one, the default when the member is absent, and unknown for any other
// value, which a host cannot read as a boolean and this package cannot trust.
func (h hintRule) effective(v value) (val, known bool) {
	if !v.present {
		return h.def, true
	}
	b, ok := v.v.(bool)
	return b, ok
}

// loosened reports whether the move from f to t gives the tool more latitude
// than the approved definition had: the hint stood at its safe value and now
// provably does not, or cannot be shown to (an unreadable value fails closed).
func (h hintRule) loosened(f, t value) bool {
	fv, fknown := h.effective(f)
	if !fknown || fv != h.safe {
		return false
	}
	tv, tknown := h.effective(t)
	return !tknown || tv != h.safe
}

// hintText renders one side of a hint transition from a closed vocabulary:
// true, false, absent, or other for a value that is not a boolean.
func hintText(v value) string {
	if !v.present {
		return "absent"
	}
	if b, ok := v.v.(bool); ok {
		return strconv.FormatBool(b)
	}
	return "other"
}

// compareAnnotations grades the annotations object: each of the four hints
// that differs is annotations-loosened (CRITICAL) when it moved away from its
// safe value and annotations-changed (WARNING) otherwise; every other member
// that differs (title included) is annotations-changed; a side that is not an
// object at all is one annotations-changed finding for the member itself, and
// its hints are read as absent, so a definition that drops the whole object
// still shows which hints it loosened.
func (c *classifier) compareAnnotations(path string, f, t value) {
	fa, fok := f.object()
	ta, tok := t.object()
	if !fok || !tok {
		c.add(AnnotationsChanged, path, presence(f, t))
	}
	isHint := make(map[string]bool, len(hintRules()))
	for _, h := range hintRules() {
		isHint[h.name] = true
		fm, tm := memberOf(fa, h.name), memberOf(ta, h.name)
		if !differ(fm, tm) {
			continue
		}
		kind := AnnotationsChanged
		if h.loosened(fm, tm) {
			kind = AnnotationsLoosened
		}
		c.add(kind, path+segment(h.name), hintText(fm)+" -> "+hintText(tm))
	}
	for _, k := range mergedKeys(fa, ta) {
		if isHint[k] {
			continue
		}
		fm, tm := memberOf(fa, k), memberOf(ta, k)
		if differ(fm, tm) {
			c.add(AnnotationsChanged, path+segment(k), presence(fm, tm))
		}
	}
}
