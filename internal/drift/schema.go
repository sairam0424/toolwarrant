package drift

import (
	"reflect"
	"sort"
	"strings"
)

// The inputSchema members the parameter rules read.
const (
	keyProperties = "properties"
	keyRequired   = "required"
	keyType       = "type"
	typeAbsent    = "absent"
	typeOther     = "other"
	// typeSeparator joins the members of a JSON Schema type array.
	typeSeparator = "|"
)

// jsonSchemaTypes is the closed vocabulary a type may be rendered from; any
// other value prints as other, so a detail never carries upstream text.
func jsonSchemaTypes() map[string]bool {
	return map[string]bool{"null": true, "boolean": true, "object": true, "array": true,
		"number": true, "integer": true, "string": true}
}

// compareInputSchema applies the parameter rules to inputSchema. A side that
// is not an object is one input-schema-changed finding for the member itself
// and is read as an empty schema, so its parameters count as added or
// removed; every member other than properties and required that differs is
// input-schema-changed.
func (c *classifier) compareInputSchema(path string, f, t value) {
	fs, fok := f.object()
	ts, tok := t.object()
	if !fok || !tok {
		c.add(InputSchemaChanged, path, presence(f, t))
	}
	c.compareParameters(path, fs, ts)
	for _, k := range mergedKeys(fs, ts) {
		if k == keyProperties || k == keyRequired {
			continue
		}
		fm, tm := memberOf(fs, k), memberOf(ts, k)
		if differ(fm, tm) {
			c.add(InputSchemaChanged, path+segment(k), presence(fm, tm))
		}
	}
}

// compareParameters walks inputSchema.properties of both sides together. A
// parameter present on one side only is parameter-removed, or
// required-parameter-added or optional-parameter-added by whether the new
// required list names it; one present on both is handed to compareParameter.
// A properties member that is present but not an object is one
// input-schema-changed finding and reads as empty. The required list is then
// checked for differences the parameters did not explain.
func (c *classifier) compareParameters(path string, fs, ts map[string]any) {
	fp, tp := memberOf(fs, keyProperties), memberOf(ts, keyProperties)
	fProps, fok := fp.object()
	tProps, tok := tp.object()
	propsPath := path + segment(keyProperties)
	if (fp.present && !fok) || (tp.present && !tok) {
		c.add(InputSchemaChanged, propsPath, presence(fp, tp))
	}
	fReq, tReq := requiredSet(fs), requiredSet(ts)
	explained := false
	for _, name := range mergedKeys(fProps, tProps) {
		fv, tv := memberOf(fProps, name), memberOf(tProps, name)
		p := propsPath + segment(name)
		switch {
		case !tv.present:
			c.add(ParameterRemoved, p, "removed")
			explained = explained || fReq[name]
		case !fv.present && tReq[name]:
			c.add(RequiredParameterAdded, p, "added")
			explained = true
		case !fv.present:
			c.add(OptionalParameterAdded, p, "added")
		default:
			explained = c.compareParameter(p, fv, tv, fReq[name], tReq[name]) || explained
		}
	}
	c.compareRequired(path, fs, ts, fProps, tProps, explained)
}

// compareParameter grades one parameter present on both sides: a different
// type is parameter-type-changed, newly required is parameter-made-required,
// made optional is input-schema-changed, and any other difference (an enum, a
// constraint, a nested schema) is input-schema-changed. It reports whether
// the required list changed for this parameter.
func (c *classifier) compareParameter(p string, fv, tv value, fReq, tReq bool) bool {
	ft, tt := typeOf(fv), typeOf(tv)
	if ft != tt {
		c.add(ParameterTypeChanged, p+segment(keyType), ft+" -> "+tt)
	}
	switch {
	case !fReq && tReq:
		c.add(ParameterMadeRequired, p, "made required")
	case fReq && !tReq:
		c.add(InputSchemaChanged, p, "made optional")
	}
	if !sameExceptType(fv, tv) {
		c.add(InputSchemaChanged, p, "changed")
	}
	return fReq != tReq
}

// sameExceptType reports whether two parameter schemas are equal once their
// type members are set aside, so a type change alone is one finding.
func sameExceptType(fv, tv value) bool {
	fo, fok := fv.object()
	to, tok := tv.object()
	if !fok || !tok {
		return reflect.DeepEqual(fv.v, tv.v)
	}
	for _, k := range mergedKeys(fo, to) {
		if k == keyType {
			continue
		}
		if differ(memberOf(fo, k), memberOf(to, k)) {
			return false
		}
	}
	return true
}

// typeOf renders a parameter's JSON Schema type from the closed vocabulary: a
// type name, a sorted list of names joined by |, absent when the schema has
// no type, and other for a schema that is not an object or a type that is not
// a known name.
func typeOf(v value) string {
	obj, ok := v.object()
	if !ok {
		return typeOther
	}
	ty := memberOf(obj, keyType)
	if !ty.present {
		return typeAbsent
	}
	known := jsonSchemaTypes()
	switch t := ty.v.(type) {
	case string:
		if known[t] {
			return t
		}
	case []any:
		names := make([]string, 0, len(t))
		for _, el := range t {
			s, isString := el.(string)
			if !isString || !known[s] {
				return typeOther
			}
			names = append(names, s)
		}
		sort.Strings(names)
		return strings.Join(names, typeSeparator)
	}
	return typeOther
}

// requiredSet reads inputSchema.required as a set of names; members that are
// not strings are ignored here and surface through compareRequired.
func requiredSet(schema map[string]any) map[string]bool {
	out := map[string]bool{}
	list, _ := memberOf(schema, keyRequired).v.([]any)
	for _, el := range list {
		if s, ok := el.(string); ok {
			out[s] = true
		}
	}
	return out
}

// compareRequired adds one input-schema-changed finding for the required list
// when it differs in a way no parameter finding explains: a name that is not a
// parameter on either side, a value that is not an array (its names are then
// read as none), a reorder, or any difference while no parameter changed its
// required status.
func (c *classifier) compareRequired(path string, fs, ts, fProps, tProps map[string]any, explained bool) {
	fr, tr := memberOf(fs, keyRequired), memberOf(ts, keyRequired)
	if !differ(fr, tr) {
		return
	}
	_, fIsList := fr.v.([]any)
	_, tIsList := tr.v.([]any)
	malformed := (fr.present && !fIsList) || (tr.present && !tIsList)
	fReq, tReq := requiredSet(fs), requiredSet(ts)
	strayDiffers := false
	for _, name := range mergedKeys(boolKeys(fReq), boolKeys(tReq)) {
		_, inFrom := fProps[name]
		_, inTo := tProps[name]
		if !inFrom && !inTo && fReq[name] != tReq[name] {
			strayDiffers = true
		}
	}
	if strayDiffers || malformed || !explained {
		c.add(InputSchemaChanged, path+segment(keyRequired), presence(fr, tr))
	}
}

// boolKeys views a name set as an object, for mergedKeys.
func boolKeys(set map[string]bool) map[string]any {
	out := make(map[string]any, len(set))
	for k := range set {
		out[k] = true
	}
	return out
}
