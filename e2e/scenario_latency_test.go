//go:build e2e

package e2e

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// latencyPairs is the sample size per mode: 100 tools/list plus tools/call
	// pairs, as the task fixes it.
	latencyPairs = 100
	// warmupPairs are measured and discarded so connection set-up and the
	// processor's digest cache do not land in the sample.
	warmupPairs = 3
)

// latencySample holds the per-operation durations of one mode, in ms.
type latencySample struct {
	list, call []float64
}

// scenarioM: 100 list+call pairs through the gateway with the processor and
// with the CEL-only variant, p50 and p95 for both, and the added latency.
// Limit L12 says this number had not been re-measured with toolwarrant serve.
func scenarioM(t *testing.T, s *stack) {
	cs := s.eventuallyServes(t, "mock", "add", "echo")
	guarded := measurePairs(t, cs, latencyPairs)
	original := s.config(t)
	s.writeConfig(t, stripGuardrails(original))
	cs = s.eventuallyServes(t, "mock", "add", "echo")
	plain := measurePairs(t, cs, latencyPairs)
	s.note(t, "%s", formatLatency(guarded, plain, latencyPairs))
	s.emit(t, nil)
	s.eventuallyServes(t, "mock", "add", "echo")
}

// measurePairs times n list+call pairs on one session.
func measurePairs(t *testing.T, cs *mcp.ClientSession, n int) latencySample {
	t.Helper()
	var sample latencySample
	for i := 0; i < n+warmupPairs; i++ {
		t0 := time.Now()
		if _, err := listTools(cs); err != nil {
			t.Fatalf("pair %d: tools/list: %v", i, err)
		}
		t1 := time.Now()
		if o := callTool(cs, "echo"); !o.allowed {
			t.Fatalf("pair %d: tools/call echo: %s", i, o)
		}
		t2 := time.Now()
		if i < warmupPairs {
			continue
		}
		sample.list = append(sample.list, ms(t1.Sub(t0)))
		sample.call = append(sample.call, ms(t2.Sub(t1)))
	}
	return sample
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// percentile is the nearest-rank percentile of an unsorted sample.
func percentile(sample []float64, p float64) float64 {
	if len(sample) == 0 {
		return 0
	}
	sorted := append([]float64(nil), sample...)
	sort.Float64s(sorted)
	rank := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// formatLatency renders the table README limit L12 asks for.
func formatLatency(guarded, plain latencySample, n int) string {
	row := func(name string, s latencySample) string {
		return fmt.Sprintf("%-26s %9.2f %9.2f %9.2f %9.2f", name,
			percentile(s.list, 50), percentile(s.list, 95), percentile(s.call, 50), percentile(s.call, 95))
	}
	added := fmt.Sprintf("%-26s %+9.2f %+9.2f %+9.2f %+9.2f", "added by the processor",
		percentile(guarded.list, 50)-percentile(plain.list, 50), percentile(guarded.list, 95)-percentile(plain.list, 95),
		percentile(guarded.call, 50)-percentile(plain.call, 50), percentile(guarded.call, 95)-percentile(plain.call, 95))
	return strings.Join([]string{
		fmt.Sprintf("M: latency through the gateway, loopback, 3-tool page, %d list+call pairs per mode, ms", n),
		fmt.Sprintf("%-26s %9s %9s %9s %9s", "mode", "list p50", "list p95", "call p50", "call p95"),
		row("toolwarrant serve", guarded),
		row("CEL rule only", plain),
		added,
	}, "\n")
}

// scenarioN: every processor stops cleanly on SIGTERM, exits 0 and prints its
// counters. mock's processor received mockb's hooks in scenario J (wrong
// backend) and hostile's hid vendor_tool in scenario L (mismatched); the
// counters must say so.
func scenarioN(t *testing.T, s *stack) {
	for _, name := range s.names {
		u := s.servers[name]
		if u.processor == nil || !u.processor.running() {
			t.Errorf("processor %s is not running at shutdown", name)
			continue
		}
		out := s.stopProcessor(t, name)
		stats := lastLineWith(out, "stats:")
		if stats == "" {
			t.Errorf("processor %s printed no stats line on SIGTERM:\n%s", name, out)
			continue
		}
		s.note(t, "N: processor %s on SIGTERM: %s", name, stats)
		switch name {
		case "mock":
			if n := statValue(t, stats, "wrong backend"); n == 0 {
				t.Errorf("mock's processor counted no wrong-backend hooks although scenario J pointed mockb's route at it")
			}
		case "hostile":
			if n := statValue(t, stats, "mismatched"); n == 0 {
				t.Errorf("hostile's processor counted no mismatched tools although scenario L served vendor_tool")
			}
		}
	}
}
