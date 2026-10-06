# Golden files

Each `.yaml` file here is the exact output of `emit.AgentGateway` for the input
of the same name in `goldenCases` (emit_test.go). Regenerate them deliberately
with `EMIT_UPDATE_GOLDEN=1 go test ./internal/emit/` and review the diff: a
change here is a change to what every operator's gateway reads.

What the tests in this package prove about these files, and what they do not:

- `binary_test.go` runs the real agentgateway v1.6.0 binary in `--validate-only`
  mode over every file. That proves the YAML shape, the CEL syntax of the allow
  rules and of the secret literals, and the `config` listener addresses parse.
  It proves nothing about runtime semantics: `--validate-only` accepts unknown
  CEL variables (`mcp.tool.nmae`), type errors (`mcp.tool.name == 5`),
  non-boolean rules, empty and deny-only rule sets, `failOpen` and unknown
  method names.
- Which methods the allow rule filters at runtime, that `mcp.tool.name` binds to
  the served tool name, that `initialize` and `resources/*` still work, and
  that the processor really receives `toolwarrant_secret`, are verified only by
  the end-to-end test in `cmd` (gateway running as a server against a mock
  upstream), not here. The emitted file is defence in depth behind the
  processor; the processor is the guard.
- `integrity_test.go` checks that every file here verifies with `emit.Verify`,
  so a hand edit of a golden file fails the suite the same way an edited
  deployed config fails the operator's canary.
