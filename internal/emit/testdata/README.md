# Golden files

Each `.yaml` file here is the exact output of `emit.AgentGateway` for the input
of the same name in `goldenCases` (emit_test.go). Regenerate them deliberately
with `EMIT_UPDATE_GOLDEN=1 go test ./internal/emit/` and review the diff: a
change here is a change to what every operator's gateway reads.

The files use the schema's `gateways` form: one gateway named `toolwarrant`
with `port` and `bindAddress`, a top-level `routes` list whose entries attach
to it with `gateways: "toolwarrant"`, and under each route the same `matches`,
`policies` (mcpAuthorization, mcpGuardrails) and `backends` the deprecated
`binds[]` form carried. `bindAddress` is `127.0.0.1` unless the input says
otherwise: `loopback_v6.yaml` binds `::1`, and `all_interfaces.yaml` binds
`0.0.0.0`, which the input had to confirm with `AllowAllInterfaces` and which
makes `AgentGateway` return a `Warning`.

What the tests in this package prove about these files, and what they do not:

- `binary_test.go` runs the real agentgateway v1.6.0 binary in `--validate-only`
  mode over every file. That proves the YAML shape, the CEL syntax of the allow
  rules and of the secret literals, that the `config` listener addresses and
  `bindAddress` parse (host names, host:port forms, brackets, zones and the
  empty string are refused), and that every route's `gateways` reference
  resolves (an unknown name, a missing field and a gateway no route names all
  fail). It proves nothing about runtime semantics: `--validate-only` accepts
  unknown CEL variables (`mcp.tool.nmae`), type errors (`mcp.tool.name == 5`),
  non-boolean rules, empty and deny-only rule sets, `failOpen`, unknown method
  names, duplicate route names, and bind addresses that cannot be bound at
  start-up (`::ffff:127.0.0.1`, `224.0.0.1`, `255.255.255.255`, `fe80::1`
  without a zone), which is why the emitter refuses those itself.
- That the socket is really bound to `bindAddress` and not to every interface,
  that the routes attached by name are served on it, which methods the allow
  rule filters at runtime, that `mcp.tool.name` binds to the served tool name,
  that `initialize` and `resources/*` still work, and that the processor really
  receives `toolwarrant_secret`, are verified only by the end-to-end test in
  `cmd` (gateway running as a server against a mock upstream), not here. The
  emitted file is defence in depth behind the processor; the processor is the
  guard.
- `integrity_test.go` checks that every file here verifies with `emit.Verify`,
  so a hand edit of a golden file fails the suite the same way an edited
  deployed config fails the operator's canary.
