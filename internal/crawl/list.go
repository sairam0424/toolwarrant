package crawl

import (
	"context"
	"encoding/json"
	"fmt"
)

// vetted is one listed tool after vetTool and before the listing-wide check
// for repeated names.
type vetted struct {
	name   string
	raw    json.RawMessage
	reason Reason
	detail string
}

// listAll walks tools/list to the end, enforcing every bound, and vets each
// tool as it arrives so that the work a hostile page causes is bounded by the
// byte budget and done once.
func (s *session) listAll(ctx context.Context) ([]vetted, int, error) {
	var list []vetted
	cursors := map[string]struct{}{}
	cursor := ""
	total := 0
	for pages := 1; ; pages++ {
		if err := ctx.Err(); err != nil {
			return nil, 0, fmt.Errorf("crawl: tools/list: %w", err)
		}
		result, _, err := s.call(ctx, methodToolsList, toolsListParams{Cursor: cursor})
		if err != nil {
			return nil, 0, err
		}
		raws, next, err := parseToolsPage(result)
		if err != nil {
			return nil, 0, err
		}
		for _, raw := range raws {
			if len(list) >= s.cfg.maxTools {
				return nil, 0, fmt.Errorf("%w: more than %d", ErrTooManyTools, s.cfg.maxTools)
			}
			if total += len(raw); total > s.cfg.maxTotal {
				return nil, 0, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, s.cfg.maxTotal)
			}
			name, reason, detail := vetTool(raw, s.cfg.maxToolBytes)
			list = append(list, vetted{name: name, raw: raw, reason: reason, detail: detail})
		}
		if next == "" {
			return list, pages, nil
		}
		if _, seen := cursors[next]; seen {
			return nil, 0, ErrCursorLoop
		}
		cursors[next] = struct{}{}
		if pages >= s.cfg.maxPages {
			return nil, 0, fmt.Errorf("%w: more than %d", ErrTooManyPages, s.cfg.maxPages)
		}
		cursor = next
	}
}

// finish applies the one rule that needs the whole listing, a name listed more
// than once makes every copy unusable, and splits the listing into usable and
// unusable tools, both in server order. Every copy is refused, not only the
// later ones: a gateway may route a call to any of them, and by name the
// approved copy cannot be told from the impostor.
func finish(list []vetted) ([]Tool, []UnusableTool) {
	copies := make(map[string]int, len(list))
	for _, v := range list {
		if v.name != "" {
			copies[v.name]++
		}
	}
	tools := []Tool{}
	var unusable []UnusableTool
	for _, v := range list {
		reason, detail := v.reason, v.detail
		if n := copies[v.name]; v.name != "" && n > 1 {
			reason, detail = ReasonDuplicateName, fmt.Sprintf("the name is listed %d times", n)
		}
		if reason == "" {
			tools = append(tools, Tool{Name: v.name, Raw: v.raw})
			continue
		}
		unusable = append(unusable, UnusableTool{Name: v.name, Raw: v.raw, Reason: reason, Detail: detail})
	}
	return tools, unusable
}
