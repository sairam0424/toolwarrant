package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// Limits on one crawl (D6). They are exported so that the crawler vets with
// the same numbers and a tool it accepts is never refused here for size.
const (
	// MaxToolBytes bounds one tool definition. Real definitions are kilobytes;
	// the cap stops one upstream from filling the file with padding.
	MaxToolBytes = 256 << 10
	// MaxToolsPerCrawl bounds the entries (usable and unusable) of one crawl.
	MaxToolsPerCrawl = 10000
	// MaxCrawlBytes bounds the definitions of one crawl taken together.
	MaxCrawlBytes = 32 << 20
	// MaxJSONDepth bounds nesting inside one definition, counting the outermost
	// object as level 1, as the crawler does.
	MaxJSONDepth = 32
	// MaxProposalsPerDecision is how many new versions a tool may gain before a
	// person approves, rejects or rolls back. Past it a crawl that brings yet
	// another digest marks the tool unusable instead of storing the definition,
	// so a hostile upstream that changes every crawl cannot grow the file
	// without bound, while the tool is still hidden until someone decides.
	MaxProposalsPerDecision = 20
)

// Reason classes the catalog attaches to a listed tool it cannot use. They
// are stored and printed as they are, so they are fixed tokens.
const (
	reasonInvalidName   = "invalid-name"
	reasonUnreadable    = "unreadable"
	reasonTooLarge      = "too-large"
	reasonTooDeep       = "too-deep"
	reasonNotCanonical  = "not-canonical"
	reasonNameMismatch  = "name-mismatch"
	reasonDuplicateName = "duplicate-name"
	reasonBudget        = "proposal-budget-exhausted"
	// reasonUnusable is the fallback for a crawler reason that is not a token.
	reasonUnusable = "unusable"
)

// preparedTool is a crawled tool that passed validation, with the canonical
// form and digest computed here from the raw bytes. The catalog never trusts a
// digest it did not compute itself.
type preparedTool struct {
	name      string
	raw       []byte
	canonical []byte
	digest    string
}

// toolError says why one definition cannot be used: a class and a detail in
// fixed words that carry numbers but never upstream bytes.
type toolError struct {
	reason string
	detail string
}

func (e *toolError) Error() string { return e.reason + ": " + e.detail }

func toolErrorf(reason, format string, args ...any) *toolError {
	return &toolError{reason: reason, detail: fmt.Sprintf(format, args...)}
}

// prepareTool validates one listed tool and computes its digest. The caller
// has already validated the name.
func prepareTool(ct CrawledTool) (preparedTool, *toolError) {
	raw := bytes.Clone(ct.Raw) // the caller may keep writing to its slice
	if terr := checkToolJSON(raw, ct.Name); terr != nil {
		return preparedTool{}, terr
	}
	canonical, err := gate.CanonicalTool(raw)
	if err != nil {
		return preparedTool{}, toolErrorf(reasonNotCanonical, "RFC 8785 canonicalisation refused the definition")
	}
	return preparedTool{name: ct.Name, raw: raw, canonical: canonical, digest: gate.DigestOfCanonical(canonical)}, nil
}

// checkToolJSON requires a well-formed, unambiguous JSON object within the
// caps whose "name" is the name the crawler reported.
func checkToolJSON(raw []byte, wantName string) *toolError {
	if len(raw) == 0 {
		return toolErrorf(reasonUnreadable, "the definition is empty")
	}
	if len(raw) > MaxToolBytes {
		return toolErrorf(reasonTooLarge, "%d bytes, the cap is %d", len(raw), MaxToolBytes)
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return toolErrorf(reasonUnreadable, "not valid UTF-8 JSON")
	}
	if terr := checkStructure(raw); terr != nil {
		return terr
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return toolErrorf(reasonUnreadable, "not a JSON object")
	}
	rawName, ok := obj["name"]
	if !ok || !bytes.HasPrefix(bytes.TrimSpace(rawName), []byte(`"`)) {
		return toolErrorf(reasonUnreadable, `no string "name" member`)
	}
	var name string
	if err := json.Unmarshal(rawName, &name); err != nil || name != wantName {
		return toolErrorf(reasonNameMismatch, `the "name" member differs from the listed name`)
	}
	return nil
}

// checkStructure walks the document once for two rules: no key repeats inside
// one object at any depth (Go keeps the last duplicate, other parsers keep the
// first, so a repeated key lets one definition read differently to the digest
// and to the client that shows the tool to a model), and containers nest at
// most MaxJSONDepth deep.
func checkStructure(raw []byte) *toolError {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if terr := walkJSON(dec, 1); terr != nil {
		return terr
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return toolErrorf(reasonUnreadable, "data after the JSON value")
	}
	return nil
}

// walkJSON reads one value whose containers, if any, sit at nesting level depth.
func walkJSON(dec *json.Decoder, depth int) *toolError {
	tok, err := dec.Token()
	if err != nil {
		return toolErrorf(reasonUnreadable, "not well-formed JSON")
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil
	}
	if depth > MaxJSONDepth {
		return toolErrorf(reasonTooDeep, "nests deeper than %d levels", MaxJSONDepth)
	}
	switch delim {
	case '{':
		if terr := walkObject(dec, depth); terr != nil {
			return terr
		}
	case '[':
		for dec.More() {
			if terr := walkJSON(dec, depth+1); terr != nil {
				return terr
			}
		}
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return toolErrorf(reasonUnreadable, "not well-formed JSON")
	}
	return nil
}

func walkObject(dec *json.Decoder, depth int) *toolError {
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return toolErrorf(reasonUnreadable, "not well-formed JSON")
		}
		key, _ := keyTok.(string)
		if _, dup := seen[key]; dup {
			return toolErrorf(reasonNotCanonical, "repeats a key at nesting level %d", depth)
		}
		seen[key] = struct{}{}
		if terr := walkJSON(dec, depth+1); terr != nil {
			return terr
		}
	}
	return nil
}
