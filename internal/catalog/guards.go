package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
)

// The guard objects: the triggers that make history append-only and the
// indexes the uniqueness rules rest on. Open, Snapshot and Approved refuse a
// database that has lost any of them or holds one under another definition
// (ErrCorrupt). A dropped trigger would silently turn history tables mutable;
// a same-named trigger that never fires would do the same while a check of
// names alone still passed, which is why the stored DDL text is compared and
// not the name.

// guardIndexStatements creates the indexes the uniqueness rules rest on. The
// two partial unique indexes enforce "one pending, one approved version per
// tool"; they stay partial on purpose (a full index on (tool_id, status) would
// forbid two superseded versions), and the REPLACE path they open is closed by
// the tool_versions_no_replace trigger.
func guardIndexStatements() []string {
	return []string{
		`CREATE UNIQUE INDEX one_pending_version ON tool_versions (tool_id) WHERE status = 'pending'`,
		`CREATE UNIQUE INDEX one_approved_version ON tool_versions (tool_id) WHERE status = 'approved'`,
		`CREATE INDEX approvals_by_version ON approvals (version_id, id)`,
	}
}

// guardStatements adds the append-only and immutability triggers. Every
// BEFORE INSERT guard mirrors a uniqueness rule in its WHEN clause because
// INSERT OR REPLACE resolves a UNIQUE conflict by deleting the old row without
// firing delete triggers (recursive_triggers is off in any SQLite shell); a
// BEFORE INSERT trigger runs before conflict resolution, so RAISE there stops
// the statement before anything is deleted. The UPDATE guards compare values
// instead of naming columns, because an UPDATE OF column list does not see
// "SET rowid = ..." (nor _rowid_ or oid) although it rewrites the id.
func guardStatements() []string {
	return []string{
		triggerAbort("audit_log_no_update", "BEFORE UPDATE ON audit_log", "", "audit_log is append-only"),
		triggerAbort("audit_log_no_delete", "BEFORE DELETE ON audit_log", "", "audit_log is append-only"),
		triggerAbort("audit_log_sequential", "BEFORE INSERT ON audit_log",
			"WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log)",
			"audit_log entries must be appended in sequence"),
		triggerAbort("tool_versions_no_delete", "BEFORE DELETE ON tool_versions", "", "tool_versions are immutable"),
		triggerAbort("tool_versions_immutable", "BEFORE UPDATE ON tool_versions",
			"WHEN "+changedAny("id", "tool_id", "version_no", "digest", "digest_profile", "canonical", "raw",
				"proposed_by", "first_seen_at", "crawl_id"),
			"tool_versions are immutable"),
		triggerAbort("tool_versions_no_replace", "BEFORE INSERT ON tool_versions",
			`WHEN EXISTS (SELECT 1 FROM tool_versions WHERE id = NEW.id)
			   OR EXISTS (SELECT 1 FROM tool_versions WHERE tool_id = NEW.tool_id AND digest = NEW.digest)
			   OR EXISTS (SELECT 1 FROM tool_versions WHERE tool_id = NEW.tool_id AND version_no = NEW.version_no)
			   OR (NEW.status IN ('pending', 'approved')
			       AND EXISTS (SELECT 1 FROM tool_versions WHERE tool_id = NEW.tool_id AND status = NEW.status))`,
			"tool_versions cannot be replaced"),
		triggerAbort("proposers_no_update", "BEFORE UPDATE ON tool_version_proposers", "", "proposers are append-only"),
		triggerAbort("proposers_no_delete", "BEFORE DELETE ON tool_version_proposers", "", "proposers are append-only"),
		triggerAbort("proposers_append_only", "BEFORE INSERT ON tool_version_proposers",
			`WHEN EXISTS (SELECT 1 FROM tool_version_proposers WHERE version_id = NEW.version_id AND actor = NEW.actor)
			   OR NEW.position IS NOT (SELECT COUNT(*) FROM tool_version_proposers WHERE version_id = NEW.version_id)`,
			"proposers are appended once, in order"),
		triggerAbort("approvals_no_update", "BEFORE UPDATE ON approvals", "", "approvals are append-only"),
		triggerAbort("approvals_no_delete", "BEFORE DELETE ON approvals", "", "approvals are append-only"),
		triggerAbort("approvals_no_replace", "BEFORE INSERT ON approvals",
			"WHEN EXISTS (SELECT 1 FROM approvals WHERE id = NEW.id)", "approvals cannot be replaced"),
	}
}

// changedAny builds a WHEN condition that is true when any listed column of
// the row would change value. IS NOT treats NULL as a value.
func changedAny(columns ...string) string {
	parts := make([]string, len(columns))
	for i, c := range columns {
		parts[i] = fmt.Sprintf("NEW.%s IS NOT OLD.%s", c, c)
	}
	return strings.Join(parts, " OR ")
}

// triggerAbort builds a trigger whose only job is to abort the statement.
func triggerAbort(name, event, when, message string) string {
	return fmt.Sprintf("CREATE TRIGGER %s %s %s BEGIN SELECT RAISE(ABORT, '%s'); END", name, event, when, message)
}

// guardObject is one guard as the schema defines it: the kind and name under
// which sqlite_master lists it, and the statement that creates it.
type guardObject struct {
	kind, name, ddl string
}

// label is how reports name the object: "trigger X" or "index X".
func (g guardObject) label() string { return g.kind + " " + g.name }

// guardObjects lists every guard in creation order. The names are parsed from
// the statements that create the objects, so the list of names and the DDL
// that is compared with the file can never drift apart.
func guardObjects() []guardObject {
	stmts := slices.Concat(guardIndexStatements(), guardStatements())
	out := make([]guardObject, 0, len(stmts))
	for _, ddl := range stmts {
		kind, name := parseGuardDDL(ddl)
		out = append(out, guardObject{kind: kind, name: name, ddl: ddl})
	}
	return out
}

// parseGuardDDL reads the kind and name out of "CREATE TRIGGER name ..." or
// "CREATE [UNIQUE] INDEX name ...", lower-casing the kind as sqlite_master does.
func parseGuardDDL(ddl string) (kind, name string) {
	f := strings.Fields(ddl)
	if len(f) > 1 && f[1] == "UNIQUE" {
		f = f[1:]
	}
	if len(f) < 3 {
		return "", ""
	}
	return strings.ToLower(f[1]), f[2]
}

// guardTriggers names the guard triggers, in creation order.
func guardTriggers() []string { return guardNames("trigger") }

// guardIndexes names the guard indexes, in creation order.
func guardIndexes() []string { return guardNames("index") }

func guardNames(kind string) []string {
	var names []string
	for _, g := range guardObjects() {
		if g.kind == kind {
			names = append(names, g.name)
		}
	}
	return names
}

// verifyGuards requires every guard object to exist and to be defined exactly
// as the schema defines it. It runs at Open and on every Snapshot and Approved
// read: a reload costs one scan of sqlite_master, and the processor must never
// serve from a file whose guards were replaced after it opened.
func verifyGuards(ctx context.Context, q queryer) error {
	missing, redefined, err := checkGuards(ctx, q)
	if err != nil {
		return err
	}
	var problems []string
	for _, label := range missing {
		problems = append(problems, "guard "+label+" is missing")
	}
	for _, label := range redefined {
		problems = append(problems, "guard "+label+" was redefined")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s; the file was edited outside toolwarrant", ErrCorrupt, strings.Join(problems, ", "))
	}
	return nil
}

// checkGuards compares the guard objects the file holds with the schema's:
// missing lists the labels of those that are absent, redefined those whose
// stored statement differs from the schema's once whitespace is normalised.
// Other triggers and indexes are ignored; they cannot weaken a guard that is
// present and intact.
func checkGuards(ctx context.Context, q queryer) (missing, redefined []string, err error) {
	stored, err := storedObjectDDL(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	for _, g := range guardObjects() {
		ddl, ok := stored[g.kind+"/"+g.name]
		switch {
		case !ok:
			missing = append(missing, g.label())
		case normalizeDDL(ddl) != normalizeDDL(g.ddl):
			redefined = append(redefined, g.label())
		}
	}
	return missing, redefined, nil
}

// storedObjectDDL reads the statement behind every trigger and index in the
// file, keyed by kind/name. SQLite keeps the text of the CREATE statement that
// made the object; an index it created for a constraint has none.
func storedObjectDDL(ctx context.Context, q queryer) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT type, name, sql FROM sqlite_master WHERE type IN ('trigger', 'index')`)
	if err != nil {
		return nil, fmt.Errorf("catalog: inspect guard objects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	stored := map[string]string{}
	for rows.Next() {
		var (
			kind, name string
			ddl        sql.NullString
		)
		if err := rows.Scan(&kind, &name, &ddl); err != nil {
			return nil, fmt.Errorf("catalog: inspect guard objects: %w", err)
		}
		stored[kind+"/"+name] = ddl.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: inspect guard objects: %w", err)
	}
	return stored, nil
}

// normalizeDDL collapses every run of whitespace to one space so that the text
// SQLite stores compares equal to the statement that created the object,
// however either was laid out. Nothing else is normalised: a changed keyword,
// condition or message is a different guard.
func normalizeDDL(s string) string { return strings.Join(strings.Fields(s), " ") }
