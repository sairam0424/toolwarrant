package catalog

import (
	"errors"
	"fmt"
	"strings"

	sqlite "modernc.org/sqlite"
)

// Naming the constraint a write failed (D15 e). A constraint failure inside a
// write transaction is ErrCorrupt (corruptIfConstraint): the Store validates
// everything before it writes, so a constraint that still fires is one the
// schema does not have or a guard refusing a row. The fifth review re-created
// a table with an extra constraint, and the error named no cause while audit
// verify saw nothing, so the message now carries what SQLite reports.

const (
	// Extended result codes of the constraint failures whose messages name
	// what refused the write (describeConstraint).
	sqliteConstraintCheck      = 275
	sqliteConstraintNotNull    = 1299
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintTrigger    = 1811
	sqliteConstraintUnique     = 2067
	// sqliteMessagePrefix starts the driver's text for every constraint
	// failure; the SQLite message follows it and the result code ends it.
	sqliteMessagePrefix = "constraint failed: "
)

// describeConstraint says which constraint refused a write, from SQLite's
// extended result code and its message, which names table and column for a
// UNIQUE, PRIMARY KEY or NOT NULL constraint and the expression for a CHECK
// (D15 e): an operator who sees the table named can find the re-created table
// that audit verify reports as redefined.
func describeConstraint(err error) string {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return fmt.Sprintf("a write failed a constraint the schema does not have, or a guard refused it (%v)", err)
	}
	msg := sqliteMessage(se)
	switch se.Code() {
	case sqliteConstraintTrigger:
		return fmt.Sprintf("a guard refused the write (%s)", msg)
	case sqliteConstraintUnique, sqliteConstraintPrimaryKey, sqliteConstraintNotNull:
		return fmt.Sprintf("a write to table %s failed a constraint (%s): the schema's own writes never do, so the table was re-created with another definition or a bug wrote the row", constraintTable(msg), msg)
	case sqliteConstraintCheck:
		return fmt.Sprintf("a write failed a CHECK constraint (%s): the schema's own writes never do, so a table was re-created with another definition or a bug wrote the row", msg)
	}
	return fmt.Sprintf("a write failed a constraint the schema does not have, or a guard refused it (%v)", err)
}

// sqliteMessage extracts SQLite's own message from the driver's error text,
// "constraint failed: <message> (<code>)".
func sqliteMessage(se *sqlite.Error) string {
	msg := strings.TrimPrefix(se.Error(), sqliteMessagePrefix)
	return strings.TrimSuffix(msg, fmt.Sprintf(" (%d)", se.Code()))
}

// constraintTable reads the table out of "UNIQUE constraint failed:
// table.column[, table.column]", or "" when the message has another shape.
func constraintTable(msg string) string {
	_, target, ok := strings.Cut(msg, "constraint failed: ")
	if !ok {
		return quote("")
	}
	table, _, ok := strings.Cut(target, ".")
	if !ok {
		return quote("")
	}
	return table
}
