package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// Limits on one crawl.
const (
	maxToolBytes     = 1 << 20   // one tool definition
	maxToolsPerCrawl = 10000     // tools in one crawl
	maxCrawlBytes    = 128 << 20 // all definitions in one crawl
	maxJSONDepth     = 256       // nesting inside one definition
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

// prepareCrawlTools validates every tool of a crawl before anything is
// written, and returns them sorted by name.
func prepareCrawlTools(in []CrawledTool) ([]preparedTool, error) {
	if len(in) > maxToolsPerCrawl {
		return nil, invalidf("a crawl may list at most %d tools, got %d", maxToolsPerCrawl, len(in))
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]preparedTool, 0, len(in))
	total := 0
	for _, ct := range in {
		if _, dup := seen[ct.Name]; dup {
			return nil, invalidf("tool %s appears twice in one crawl", quote(ct.Name))
		}
		seen[ct.Name] = struct{}{}
		if total += len(ct.Raw); total > maxCrawlBytes {
			return nil, invalidf("a crawl may carry at most %d bytes of tool definitions", maxCrawlBytes)
		}
		p, err := prepareTool(ct)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func prepareTool(ct CrawledTool) (preparedTool, error) {
	if err := validateToolName(ct.Name); err != nil {
		return preparedTool{}, err
	}
	raw := bytes.Clone(ct.Raw) // the caller may keep writing to its slice
	if err := checkToolJSON(raw, ct.Name); err != nil {
		return preparedTool{}, invalidf("tool %s: %v", quote(ct.Name), err)
	}
	canonical, err := gate.CanonicalTool(raw)
	if err != nil {
		return preparedTool{}, invalidf("tool %s: %v", quote(ct.Name), err)
	}
	return preparedTool{name: ct.Name, raw: raw, canonical: canonical, digest: gate.DigestOfCanonical(canonical)}, nil
}

// checkToolJSON requires a well-formed, unambiguous JSON object whose "name"
// is the name the crawler reported.
func checkToolJSON(raw []byte, wantName string) error {
	if len(raw) == 0 || len(raw) > maxToolBytes {
		return fmt.Errorf("definition must be 1 to %d bytes", maxToolBytes)
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return errors.New("definition is not valid UTF-8 JSON")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return errors.New("definition is not a JSON object")
	}
	rawName, ok := obj["name"]
	if !ok || !bytes.HasPrefix(bytes.TrimSpace(rawName), []byte(`"`)) {
		return errors.New(`definition has no string "name"`)
	}
	var name string
	if err := json.Unmarshal(rawName, &name); err != nil || name != wantName {
		return errors.New(`"name" in the definition differs from the reported name`)
	}
	return nil
}

// rejectDuplicateKeys fails on an object that repeats a key at any depth. Go
// keeps the last duplicate, other parsers keep the first, so a repeated key
// lets one definition read differently to the digest and to the client that
// shows the tool to a model.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("definition has data after the JSON value")
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("definition is nested deeper than %d levels", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("definition is not valid JSON: %w", err)
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		if err := walkObject(dec, depth); err != nil {
			return err
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

func walkObject(dec *json.Decoder, depth int) error {
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("definition is not valid JSON: %w", err)
		}
		key, _ := keyTok.(string)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("definition repeats the key %s", quote(key))
		}
		seen[key] = struct{}{}
		if err := walkJSON(dec, depth+1); err != nil {
			return err
		}
	}
	return nil
}
