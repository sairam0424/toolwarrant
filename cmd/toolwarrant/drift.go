package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/drift"
)

const (
	// driftNotClassified is the diff line while nothing is approved: the first
	// proposal is reviewed against the empty document, and a classification
	// against nothing would grade every member as added.
	driftNotClassified = "drift: not classified (nothing approved to compare with)"
	driftPrefix        = "drift: "
	changePrefix       = "change versus the approved version "
)

// driftJSON is the classification of a version against the approved one in
// show --json (crawl --json has its own changeJSON for crawl-level changes): the grade in lower case and the kinds, the most severe first.
type driftJSON struct {
	Severity string   `json:"severity"`
	Kinds    []string `json:"kinds"`
}

// versionChanges is the classification of every version of a tool against the
// approved one. reports has one entry per version in the versions' order; it
// is nil for the approved version itself and for every version while nothing
// is approved, when approvedNo is 0.
type versionChanges struct {
	approvedNo int
	reports    []*drift.Report
}

// classifyVersions compares every version with the one in status approved.
// The classification is advice for the reader of show; the catalog's state
// and the digest decide what is served.
func classifyVersions(versions []catalog.VersionView, approved string) (versionChanges, error) {
	vc := versionChanges{reports: make([]*drift.Report, len(versions))}
	if approved == "" {
		return vc, nil
	}
	base, err := versionByDigest(versions, approved)
	if err != nil {
		return versionChanges{}, err
	}
	vc.approvedNo = base.No
	for i, v := range versions {
		if v.Digest == approved {
			continue
		}
		r, err := compareVersions(base, v)
		if err != nil {
			return versionChanges{}, err
		}
		vc.reports[i] = &r
	}
	return vc, nil
}

// compareVersions classifies v against base. The catalog re-hashes every
// canonical form it hands out, so a document the classifier refuses is a
// fault to stop on; the error names the version numbers, never the bytes.
func compareVersions(base, v catalog.VersionView) (drift.Report, error) {
	r, err := drift.Compare(base.Canonical, v.Canonical)
	if err != nil {
		return drift.Report{}, fmt.Errorf("classify version %d against the approved version %d: %w", v.No, base.No, err)
	}
	return r, nil
}

// changeCell renders the CHANGE column of show: the grade, or - for the
// approved version and for every version while nothing is approved.
func changeCell(r *drift.Report) string {
	if r == nil {
		return emptyCell
	}
	return r.Max().String()
}

// driftJSONOf renders one version's classification for show --json; nil
// where the column shows -.
func driftJSONOf(r *drift.Report) *driftJSON {
	if r == nil {
		return nil
	}
	kinds := r.Kinds()
	names := make([]string, 0, len(kinds))
	for _, k := range kinds {
		names = append(names, string(k))
	}
	return &driftJSON{Severity: strings.ToLower(r.Max().String()), Kinds: names}
}

// changeSummary is the line under the show table that groups the versions
// other than the approved one by what they change, for example `change versus
// the approved version 3: 19 versions (1-2, 4-13, 15-22) WARNING
// (description-changed); 1 version (14) CRITICAL (parameter-removed,
// description-changed)`. Groups are ordered by grade, the worst first, then
// by their first version. It is empty while nothing is approved or no other
// version exists.
func changeSummary(versions []catalog.VersionView, vc versionChanges) string {
	type group struct {
		summary string
		max     drift.Severity
		nos     []int
	}
	byKey := map[string]*group{}
	var groups []*group
	for i, r := range vc.reports {
		if r == nil {
			continue
		}
		g, ok := byKey[r.Summary()]
		if !ok {
			g = &group{summary: r.Summary(), max: r.Max()}
			byKey[r.Summary()] = g
			groups = append(groups, g)
		}
		g.nos = append(g.nos, versions[i].No)
	}
	if len(groups) == 0 {
		return ""
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].max != groups[j].max {
			return groups[i].max > groups[j].max
		}
		return groups[i].nos[0] < groups[j].nos[0]
	})
	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		parts = append(parts, countVersions(len(g.nos))+" ("+versionRanges(g.nos)+") "+g.summary)
	}
	return changePrefix + strconv.Itoa(vc.approvedNo) + ": " + strings.Join(parts, "; ")
}

func countVersions(n int) string {
	if n == 1 {
		return "1 version"
	}
	return strconv.Itoa(n) + " versions"
}

// versionRanges renders ascending version numbers as ranges: 1-2, 4-13, 15.
func versionRanges(nos []int) string {
	parts := make([]string, 0, len(nos))
	for i := 0; i < len(nos); {
		j := i
		for j+1 < len(nos) && nos[j+1] == nos[j]+1 {
			j++
		}
		if j == i {
			parts = append(parts, strconv.Itoa(nos[i]))
		} else {
			parts = append(parts, strconv.Itoa(nos[i])+"-"+strconv.Itoa(nos[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ", ")
}

// driftLine is the line diff prints after the to: header: the classification
// of the change from the from version to the to version, or that nothing is
// classified when the from side is the empty document.
func driftLine(fromDigest string, fromCanonical, toCanonical []byte) (string, error) {
	if fromDigest == "" {
		return driftNotClassified, nil
	}
	r, err := drift.Compare(fromCanonical, toCanonical)
	if err != nil {
		return "", fmt.Errorf("classify the change: %w", err)
	}
	return driftPrefix + r.Summary(), nil
}

// reportChange prints, before the suspicious-character review, how the
// version being approved differs from the one approved now. It is advice: the
// approval never depends on the grade, and a first approval prints nothing.
func reportChange(stderr *stream, approved string, versions []catalog.VersionView, v catalog.VersionView) error {
	if approved == "" || approved == v.Digest {
		return nil
	}
	base, err := versionByDigest(versions, approved)
	if err != nil {
		return err
	}
	r, err := compareVersions(base, v)
	if err != nil {
		return err
	}
	stderr.printf("%s%d: %s\n", changePrefix, base.No, r.Summary())
	return nil
}
