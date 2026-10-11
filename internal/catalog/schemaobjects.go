package catalog

import (
	"slices"
	"strings"
)

// The tables and the automatic indexes of the schema, compared with the file
// next to the guard triggers, indexes and views (D15 e). The fifth review
// re-created audit_log with an extra UNIQUE (event) constraint, copying the
// rows and the guard objects byte for byte: the table's stored DDL changed and
// SQLite built an automatic index for the constraint (sqlite_master.sql IS
// NULL), and neither was looked at, so Open, Snapshot and Integrity were clean
// while every later crawl failed on a constraint the schema does not have. Now
// the stored DDL of every table is compared with the schema's statement after
// the same whitespace normalisation as a guard's, and every automatic index
// must be one the schema's own tables create.

// kindTable is how sqlite_master lists a table.
const kindTable = "table"

// schemaTables lists every table as the schema creates it. The names are
// parsed from the statements that create the tables, so the list of names and
// the DDL compared with the file can never drift apart.
func schemaTables() []guardObject {
	var out []guardObject
	for _, stmt := range slices.Concat(catalogTables(), historyTables()) {
		kind, name := parseGuardDDL(stmt)
		if kind == kindTable {
			out = append(out, guardObject{kind: kind, name: name, ddl: stmt})
		}
	}
	return out
}

// automaticIndexes names the indexes SQLite itself creates for the schema's
// UNIQUE constraints: sqlite_autoindex_<table>_<n>, numbered per table in
// declaration order, where a WITHOUT ROWID table's primary key takes a number
// without an index entry (it is the table's own b-tree). They have no stored
// DDL, so they are matched by name; any other automatic index belongs to a
// constraint the schema does not declare and is a foreign object.
// TestSchema_AutomaticIndexesArePinned keeps this list equal to what a fresh
// file holds.
func automaticIndexes() []guardObject {
	names := []string{
		"sqlite_autoindex_servers_1",                // servers.name UNIQUE
		"sqlite_autoindex_tools_1",                  // tools UNIQUE (server_id, name)
		"sqlite_autoindex_tool_versions_1",          // tool_versions UNIQUE (tool_id, digest)
		"sqlite_autoindex_tool_versions_2",          // tool_versions UNIQUE (tool_id, version_no)
		"sqlite_autoindex_tool_version_proposers_2", // UNIQUE (version_id, actor); _1 is the primary key
	}
	out := make([]guardObject, 0, len(names))
	for _, name := range names {
		out = append(out, guardObject{kind: kindIndex, name: name})
	}
	return out
}

// schemaObjects lists everything the file must hold exactly as the schema
// defines it: the tables, the guard indexes and triggers, and the automatic
// indexes the tables create.
func schemaObjects() []guardObject {
	return slices.Concat(schemaTables(), guardObjects(), automaticIndexes())
}

// automatic reports whether the object is an index SQLite created for a
// constraint: it has no DDL to compare, only a name.
func (g guardObject) automatic() bool { return g.kind == kindIndex && g.ddl == "" }

// objectPhrase is how a report line names an object: "guard trigger X" for a
// guard, "table X" for a table.
func objectPhrase(label string) string {
	if strings.HasPrefix(label, kindTable+" ") {
		return label
	}
	return "guard " + label
}

// describe renders what checkGuards found as report lines, one per object:
// what is missing, what was redefined and what the schema never created.
// foreignNote follows a foreign object's label (Integrity adds why it matters).
func (c guardCheck) describe(foreignNote string) []string {
	var lines []string
	for _, label := range c.missing {
		lines = append(lines, objectPhrase(label)+" is missing")
	}
	for _, label := range c.redefined {
		lines = append(lines, objectPhrase(label)+" was redefined")
	}
	for _, label := range c.foreign {
		lines = append(lines, "unexpected "+label+foreignNote)
	}
	return lines
}
