package catalog

import (
	"context"
	"fmt"
	"strings"
)

// The guard objects: the triggers that make history append-only and the
// indexes the uniqueness rules rest on. Open refuses a database that has lost
// any of them (ErrCorrupt), because without them the triggers' promises are
// gone while the file still claims to be ours.

// guardIndexes names the indexes that must exist. The two partial unique
// indexes enforce "one pending, one approved version per tool"; they stay
// partial on purpose (a full index on (tool_id, status) would forbid two
// superseded versions), and the REPLACE path they open is closed by the
// tool_versions_no_replace trigger.
func guardIndexes() []string {
	return []string{"one_pending_version", "one_approved_version", "approvals_by_version"}
}

// guardTriggers names the triggers guardStatements creates.
func guardTriggers() []string {
	return []string{
		"audit_log_no_update", "audit_log_no_delete", "audit_log_sequential",
		"tool_versions_no_delete", "tool_versions_immutable", "tool_versions_no_replace",
		"proposers_no_update", "proposers_no_delete", "proposers_append_only",
		"approvals_no_update", "approvals_no_delete", "approvals_no_replace",
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

// verifyGuards checks that every guard trigger and index still exists.
func verifyGuards(ctx context.Context, q queryer) error {
	present, err := guardObjectsPresent(ctx, q)
	if err != nil {
		return err
	}
	var missing []string
	for _, name := range guardTriggers() {
		if !present["trigger/"+name] {
			missing = append(missing, "trigger "+name)
		}
	}
	for _, name := range guardIndexes() {
		if !present["index/"+name] {
			missing = append(missing, "index "+name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: guard objects are missing (%s); the file was edited outside toolwarrant", ErrCorrupt, strings.Join(missing, ", "))
	}
	return nil
}

func guardObjectsPresent(ctx context.Context, q queryer) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT type, name FROM sqlite_master WHERE type IN ('trigger', 'index')`)
	if err != nil {
		return nil, fmt.Errorf("catalog: inspect guard objects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	present := map[string]bool{}
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return nil, fmt.Errorf("catalog: inspect guard objects: %w", err)
		}
		present[kind+"/"+name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: inspect guard objects: %w", err)
	}
	return present, nil
}
