package textdiff

import (
	"strconv"
	"strings"
)

// contextLines is how many unchanged lines are shown around each change.
const contextLines = 3

// Unified returns a unified line diff of from and to with three lines of
// context. Every line, and both labels, go through Escape, so a hidden or
// terminal-controlling character shows up as a visible escape and the output
// is safe to print.
//
// The result is stable byte for byte for the same input and has no colour. It
// starts with "--- fromLabel" and "+++ toLabel" lines, then one "@@ -a,b +c,d @@"
// header per hunk (always with both numbers, even when a count is 1). Lines
// are split on "\n" only, so a carriage return is shown as \u{000D} rather than
// treated as a line break; a missing or extra trailing newline is therefore a
// visible change. There are no change lines if and only if from equals to.
//
// For very large inputs the differing block is shown as a whole-block replace
// instead of a minimal diff (see maxDiffItems and maxEditDistance).
func Unified(fromLabel, toLabel, from, to string) string {
	a, b := splitLines(from), splitLines(to)
	var sb strings.Builder
	sb.WriteString("--- ")
	sb.WriteString(escapeInline(fromLabel))
	sb.WriteString("\n+++ ")
	sb.WriteString(escapeInline(toLabel))
	sb.WriteByte('\n')
	writeHunks(&sb, diffSeq(a, b), a, b)
	return sb.String()
}

// splitLines splits on "\n". The empty string has no lines, so that "" and
// "\n" (one empty line plus the terminator) differ.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

type hunkRange struct{ start, end int }

func writeHunks(sb *strings.Builder, edits []edit, a, b []string) {
	ranges := hunkRanges(edits)
	if len(ranges) == 0 {
		return
	}
	aBefore, bBefore := consumedCounts(edits)
	for _, r := range ranges {
		writeHunk(sb, edits[r.start:r.end], aBefore[r.start], bBefore[r.start], a, b)
	}
}

// consumedCounts returns, for every position in edits (and one past the end),
// how many lines of the first and second input were used before it.
func consumedCounts(edits []edit) (aBefore, bBefore []int) {
	aBefore = make([]int, len(edits)+1)
	bBefore = make([]int, len(edits)+1)
	for i, e := range edits {
		aBefore[i+1], bBefore[i+1] = aBefore[i], bBefore[i]
		if e.kind != kindInsert {
			aBefore[i+1]++
		}
		if e.kind != kindDelete {
			bBefore[i+1]++
		}
	}
	return aBefore, bBefore
}

// hunkRanges groups the changes, with contextLines of context on each side.
// Two changes whose unchanged gap is at most twice the context share a hunk.
func hunkRanges(edits []edit) []hunkRange {
	var out []hunkRange
	lastEnd := 0
	for i := 0; i < len(edits); {
		if edits[i].kind == kindEqual {
			i++
			continue
		}
		last := lastChangeInHunk(edits, i)
		start := max(i-contextLines, lastEnd)
		end := min(last+1+contextLines, len(edits))
		out = append(out, hunkRange{start, end})
		lastEnd, i = end, end
	}
	return out
}

// lastChangeInHunk returns the index of the last change that belongs to the
// hunk whose first change is at from.
func lastChangeInHunk(edits []edit, from int) int {
	last := from
	for j := from; j < len(edits); {
		if edits[j].kind != kindEqual {
			last = j
			j++
			continue
		}
		run := j
		for run < len(edits) && edits[run].kind == kindEqual {
			run++
		}
		if run == len(edits) || run-j > 2*contextLines {
			break
		}
		j = run
	}
	return last
}

func writeHunk(sb *strings.Builder, es []edit, aBefore, bBefore int, a, b []string) {
	aCount, bCount := 0, 0
	for _, e := range es {
		if e.kind != kindInsert {
			aCount++
		}
		if e.kind != kindDelete {
			bCount++
		}
	}
	sb.WriteString("@@ -" + rangeText(aBefore, aCount) + " +" + rangeText(bBefore, bCount) + " @@\n")
	for _, e := range es {
		switch e.kind {
		case kindEqual:
			writeLine(sb, ' ', a[e.aIdx])
		case kindDelete:
			writeLine(sb, '-', a[e.aIdx])
		case kindInsert:
			writeLine(sb, '+', b[e.bIdx])
		}
	}
}

// rangeText formats "start,count". When count is zero the start is the line
// before the gap, as in GNU diff.
func rangeText(before, count int) string {
	start := before + 1
	if count == 0 {
		start = before
	}
	return strconv.Itoa(start) + "," + strconv.Itoa(count)
}

func writeLine(sb *strings.Builder, prefix byte, line string) {
	sb.WriteByte(prefix)
	sb.WriteString(Escape(line))
	sb.WriteByte('\n')
}
