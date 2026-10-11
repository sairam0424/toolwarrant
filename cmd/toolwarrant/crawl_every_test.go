package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The scheduled crawl is checked by waiting for completed iterations, not by
// a fixed time window, so a loaded machine cannot turn it into a flake.
func TestCrawlEveryRepeatsAndSurvivesFailures(t *testing.T) {
	c := newCLI(t)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer broken.Close()
	c.ok("server", "add", "down", broken.URL, "--allow-private")
	u := newUpstream(t, map[string]string{"echo": echoV1})
	c.ok("server", "add", "up", u.url(), "--allow-private")

	out, errb, stop := c.start("crawl", "down", "--every", loopEvery.String())
	waitFor(t, "two crawl lines", func() bool { return len(nonEmptyLines(out.String())) >= 2 })
	if code := stop(); code != exitOK {
		t.Fatalf("crawl --every against a broken upstream: exit %d: %s", code, errb.String())
	}
	for _, line := range nonEmptyLines(out.String()) {
		wantContains(t, "line", line, "down:", "http status 500")
		wantNotContains(t, "line", line, broken.URL)
	}

	out, errb, stop = c.start("crawl", "up", "--every", loopEvery.String(), "--json")
	waitFor(t, "two json lines", func() bool { return len(nonEmptyLines(out.String())) >= 2 })
	if code := stop(); code != exitOK {
		t.Fatalf("crawl --every --json: exit %d: %s", code, errb.String())
	}
	for i, line := range nonEmptyLines(out.String()) {
		var rep crawlJSON
		if err := json.Unmarshal([]byte(line), &rep); err != nil || !rep.Complete || rep.Server != "up" {
			t.Fatalf("line %d = %s (%v)", i, line, err)
		}
	}
	// the crawls table has one row per iteration, every one of the broken ones incomplete
	var incomplete, complete int
	queryRow(t, c.db, "SELECT COUNT(*) FROM crawls WHERE complete = 0", &incomplete)
	queryRow(t, c.db, "SELECT COUNT(*) FROM crawls WHERE complete = 1", &complete)
	if incomplete < 2 || complete < 2 {
		t.Errorf("crawls recorded: %d incomplete, %d complete", incomplete, complete)
	}
}
