//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestEndToEnd runs every scenario, in order, on one shared stack: one
// catalog, one gateway on the emitted file, the mock upstreams and the
// hostile upstream with one processor each. The order matters because each
// scenario leaves the stack in the state the next one starts from; running a
// single subtest with -run is therefore not supported. The names are the ones
// README.md and docs/ cite. Scenario Q runs right after H, while mock is the
// only server, because it restarts mock's processor with and without TLS and
// re-emits the file several times. Scenario R runs right after I, also while
// mock is the only server, because it restarts mock's processor with the two
// serve ages and waits them out, and a restart after J would reset the
// wrong-backend count that N reads from that processor at shutdown. Scenario
// N runs last, after O and P, because it deletes and re-initialises the
// catalog and stops every processor, and the two canary scenarios need both as
// they are.
func TestEndToEnd(t *testing.T) {
	if h.skip != "" {
		t.Skip(h.skip)
	}
	s := newStack(t)
	steps := []struct {
		name string
		run  func(*testing.T, *stack)
	}{
		{"A_NothingApprovedServesNothing", scenarioA},
		{"B_ApproveServesExactly", scenarioB},
		{"C_DriftHidesAndDenies", scenarioC},
		{"D_ReapproveAndRollback", scenarioD},
		{"E_DisableEnablePause", scenarioE},
		{"F_CanaryDetectsConfigEdits", scenarioF},
		{"G_FailClosedWhenProcessorDown", scenarioG},
		{"H_SharedSecret", scenarioH},
		{"Q_ProcessorTLS", scenarioQ},
		{"I_LoopbackBind", scenarioI},
		{"R_StaleCrawlDeniesCalls", scenarioR},
		{"J_CrossServerAndDuplicatePage", scenarioJ},
		{"K_CELAloneNeverMatchingRule", scenarioK},
		{"L_VendorExtensionMismatch", scenarioL},
		{"M_Latency", scenarioM},
		{"O_UnhookedCallProbe", scenarioO},
		{"P_LiveConfigComparison", scenarioP},
		{"N_StatsOnShutdown", scenarioN},
	}
	for _, step := range steps {
		s.scenario = step.name[:1]
		t.Run(step.name, func(t *testing.T) { step.run(t, s) })
	}
	s.writeReport(t)
}

// writeReport appends every recorded measurement to the file named by
// TOOLWARRANT_E2E_REPORT_FILE (demo/run.sh points it at demo/last-run.log),
// so the numbers survive outside the test log.
func (s *stack) writeReport(t *testing.T) {
	t.Helper()
	path := os.Getenv(reportEnv)
	if path == "" || len(s.notes) == 0 {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("open report file %s: %v", path, err)
		return
	}
	header := fmt.Sprintf("\n## e2e measurements, %s, %d lines\n", time.Now().UTC().Format(time.RFC3339), len(s.notes))
	if _, err := f.WriteString(header + strings.Join(s.notes, "\n") + "\n"); err != nil {
		t.Errorf("write report file %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("close report file %s: %v", path, err)
	}
}
