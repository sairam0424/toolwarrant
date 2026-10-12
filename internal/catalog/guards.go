package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// The guard objects: the triggers that make history append-only and the
// indexes the uniqueness rules and the serving path's reads rest on. Open,
// Snapshot, Approved, the views and every write transaction refuse a database
// that has lost any of them or any table, holds one under another definition,
// or holds a table, trigger, view, unique index or unaccounted automatic index
// the schema never created (ErrCorrupt). A dropped trigger would silently turn
// history tables mutable; a same-named trigger that never fires would do the
// same while a check of names alone still passed, which is why the stored DDL
// text is compared and not the name; a trigger of someone else's making on
// the tools table can rewrite the current policy inside the catalog's own
// transaction while the log records the opposite (D13), which is why nothing
// the schema did not create may exist; a unique index of someone else's
// making changes what a write does (every write that repeats the indexed
// value fails, D14), so it counts as foreign too, while a plain index only
// speeds a query up and is ignored; and a table re-created with an extra
// constraint does the same through an automatic index with no DDL of its own
// (D15 e), which is why every table's DDL is compared with the schema's and
// every automatic index must be one the schema's tables create
// (schemaobjects.go).

// guardIndexStatements creates the indexes the uniqueness rules rest on. The
// two partial unique indexes enforce "one pending, one approved version per
// tool"; they stay partial on purpose (a full index on (tool_id, status) would
// forbid two superseded versions), and the REPLACE path they open is closed by
// the tool_versions_no_replace trigger. audit_log_by_subject is what makes the
// serving path's read of the newest approval entry about each tool one index
// probe instead of a scan of the log (anchorApproved, D14).
func guardIndexStatements() []string {
	return []string{
		`CREATE UNIQUE INDEX one_pending_version ON tool_versions (tool_id) WHERE status = 'pending'`,
		`CREATE UNIQUE INDEX one_approved_version ON tool_versions (tool_id) WHERE status = 'approved'`,
		`CREATE INDEX approvals_by_version ON approvals (version_id, id)`,
		`CREATE INDEX audit_log_by_subject ON audit_log (subject, event, seq)`,
	}
}

// guardStatements adds the append-only and immutability triggers. Every
// BEFORE INSERT guard mirrors a uniqueness rule in its WHEN clause because
// INSERT OR REPLACE resolves a UNIQUE conflict by deleting the old row without
// firing delete triggers (recursive_triggers is off in any SQLite shell); a
// BEFORE INSERT trigger runs before conflict resolution, so RAISE there stops
// the statement before anything is deleted. The UPDATE guards compare values
// instead of naming columns, because an UPDATE OF column list does not see
// "SET rowid = ..." (nor _rowid_ or oid) although it rewrites the id. The
// positive-id guards are AFTER INSERT triggers on purpose: in a BEFORE INSERT
// trigger SQLite evaluates an unsupplied INTEGER PRIMARY KEY as -1, so a
// BEFORE guard on NEW.id < 1 would refuse every insert the Store makes, while
// an AFTER trigger sees the id the row got and RAISE(ABORT) there backs the
// row out again (D17 b, g; see ghostrows.go for what a row below id 1 did).
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
		triggerAbort("tool_versions_positive_id", "AFTER INSERT ON tool_versions", "WHEN NEW.id < 1",
			"tool_versions ids start at 1"),
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
		triggerAbort("approvals_positive_id", "AFTER INSERT ON approvals", "WHEN NEW.id < 1", "approvals ids start at 1"),
		// The catalog never deletes a tool row: a deleted row orphans the
		// tool's versions and lets the next crawl discover the name afresh
		// with a fresh proposer history (D14), so a delete is an edit of history.
		triggerAbort("tools_no_delete", "BEFORE DELETE ON tools", "", "tools are never deleted"),
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

// The kinds of object sqlite_master lists that the checks look at. A plain
// index someone adds can only speed a query up, so it is left alone; a table,
// a trigger or a view can change, rewrite or misrepresent rows, and a unique
// or automatic index can make every later write fail, so a foreign one of
// those is corruption.
const (
	kindTrigger = "trigger"
	kindIndex   = "index"
	kindView    = "view"
	// uniqueIndexPrefix starts the stored DDL of every unique index that was
	// created by a statement; an index SQLite made for a constraint has no DDL.
	uniqueIndexPrefix = "CREATE UNIQUE INDEX "
)

// guardCheck is what checkGuards found in the file: the schema's objects
// (tables, guard triggers and indexes, automatic indexes) that are absent,
// those stored under another definition, and the tables, triggers, views,
// unique indexes and automatic indexes the schema never created. Every slice
// holds labels ("trigger X", "table X", "index X").
type guardCheck struct {
	missing, redefined, foreign []string
}

// verifyGuards requires every table and guard object to exist and to be
// defined exactly as the schema defines it, and no table, trigger, view,
// unique index or automatic index to exist that the schema did not create. It
// runs at Open, on every Snapshot, Approved and view read, and at the end of
// every write transaction: a reload or a write costs one scan of
// sqlite_master, the processor must never serve from a file whose guards or
// tables were replaced after it opened, and a long-lived writer must never
// commit into one.
func verifyGuards(ctx context.Context, q queryer) error {
	c, err := checkGuards(ctx, q)
	if err != nil {
		return err
	}
	if problems := c.describe(""); len(problems) > 0 {
		return fmt.Errorf("%w: %s; the file was edited outside toolwarrant", ErrCorrupt, strings.Join(problems, ", "))
	}
	return nil
}

// checkGuards compares the tables, triggers, indexes and views the file holds
// with the schema's: an object that is absent is missing, one whose stored
// statement differs from the schema's once whitespace is normalised is
// redefined (an automatic index has no statement and is matched by name), and
// a table, trigger, view, unique index or automatic index the schema did not
// create is foreign. Plain indexes that are not guards are ignored: an index
// cannot change what a query returns, but a unique one changes what a write
// does, and so does the automatic index of a constraint.
func checkGuards(ctx context.Context, q queryer) (guardCheck, error) {
	stored, err := storedObjectDDL(ctx, q)
	if err != nil {
		return guardCheck{}, err
	}
	var c guardCheck
	expected := map[string]bool{}
	for _, g := range schemaObjects() {
		key := g.kind + "/" + g.name
		expected[key] = true
		ddl, ok := stored[key]
		switch {
		case !ok:
			c.missing = append(c.missing, g.label())
		case g.automatic() != isAutomaticIndexDDL(ddl), !g.automatic() && normalizeDDL(ddl) != normalizeDDL(g.ddl):
			c.redefined = append(c.redefined, g.label())
		}
	}
	for _, key := range slices.Sorted(maps.Keys(stored)) {
		kind, name, _ := strings.Cut(key, "/")
		if expected[key] || isPlainIndex(kind, stored[key]) {
			continue
		}
		c.foreign = append(c.foreign, kind+" "+name)
	}
	return c, nil
}

// isPlainIndex reports whether a stored object is an index created by a
// statement that is not unique: the one kind of foreign object tolerated.
func isPlainIndex(kind, ddl string) bool {
	return kind == kindIndex && !isAutomaticIndexDDL(ddl) && !isUniqueIndexDDL(ddl)
}

// isAutomaticIndexDDL reports whether a stored index statement is the empty
// one SQLite keeps for an index it created for a constraint.
func isAutomaticIndexDDL(ddl string) bool { return ddl == "" }

// isUniqueIndexDDL reports whether a stored index statement creates a unique
// index, however it is cased or laid out.
func isUniqueIndexDDL(ddl string) bool {
	return strings.HasPrefix(strings.ToUpper(normalizeDDL(ddl)), uniqueIndexPrefix)
}

// storedObjectDDL reads the statement behind every table, trigger, index and
// view in the file, keyed by kind/name. SQLite keeps the text of the CREATE
// statement that made the object; an index it created for a constraint has
// none and is stored as "".
func storedObjectDDL(ctx context.Context, q queryer) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT type, name, sql FROM sqlite_master WHERE type IN (?, ?, ?, ?)`,
		kindTable, kindTrigger, kindIndex, kindView)
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
