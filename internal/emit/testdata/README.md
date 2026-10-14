# Golden files

Each `.yaml` file here is the exact output of `emit.AgentGateway` for the input
of the same name in `goldenCases` (emit_test.go, listeners_test.go,
dollar_test.go). Regenerate them deliberately with
`EMIT_UPDATE_GOLDEN=1 go test ./internal/emit/` and review the diff: a change
here is a change to what every operator's gateway reads.

The files use the schema's `gateways` form: a `config` block with the admin,
stats and readiness listeners, one gateway named `toolwarrant` with `port` and
`bindAddress`, a top-level `routes` list whose entries attach to it with
`gateways: "toolwarrant"`, and under each route the same `matches`, `policies`
(mcpAuthorization, mcpGuardrails) and `backends` the deprecated `binds[]` form
carried. Every processor entry carries, after `failureMode`, the gateway's
request-header filter: `requestHeaders.allowed` names the `:method`
pseudo-header only and `requestHeaders.disallowed` names `authorization`,
`cookie` and `proxy-authorization`, so of the client's HTTP headers only
`:method` rides a hook to the processor (without the block agentgateway
forwards every header, bearer tokens and cookies included; the processor reads
none). The block never depends on the input.

- `one_server`, `two_servers`, `zero_approved`, `hostile_names`, `non_ascii`,
  `shared_rule` and `with_secret` are the original cases, every address at its
  default (`127.0.0.1`, `127.0.0.1:15000`, `127.0.0.1:15020`, `127.0.0.1:15021`).
- `loopback_v6` binds `::1`; `all_interfaces` binds `0.0.0.0`, which the input
  had to confirm with `AllowAllInterfaces` and which makes `AgentGateway`
  return a `Warning`.
- `admin_off` writes `adminAddr: "off"` (`Input.DisableAdmin`), the gateway's
  own switch for "no admin listener".
- `custom_listeners` moves the three listeners (`AdminAddr: "[::1]:16000"`,
  written in brackets, `StatsAddr: "127.0.0.2:16020"`,
  `ReadinessAddr: "127.0.0.1:16021"`), which is how two gateways run from
  emitted files on one host.
- `exposed_listeners` binds the serving port and all three listeners on
  addresses other hosts can reach, permitted by `AllowAllInterfaces`; the
  `Warning` has four lines, one per socket, in file order.
- `dollar_sign` holds a dollar sign in a URL query, in tool names and in a
  secret, written as `\u0024` (doubly escaped inside the CEL literals): the
  gateway substitutes environment variables into the raw file text, and
  binary_rules_test.go proves that a raw `$NAME` makes it refuse the file.
- `with_tls` gives both servers a `backendTLS` block (`Server.TLS`, D19):
  `policies:` after the request-header filter, `backendTLS:` under it, and
  `cert`, `key`, `root` and `hostname` as quoted scalars, before `methods`
  on the first entry and before `metadata` on the second, which also carries
  a secret. The paths are paths on a gateway host
  (`/etc/toolwarrant/gateway.pem`, `gateway-key.pem`, `processor-ca.pem`)
  and the hostname is `toolwarrant-processor`, the DNS name
  `internal/testcert` issues; the same values the canary's tests hand-build
  the block with. No other golden carries a processor `policies` block
  (`TestNoTLSMeansNoPolicies`).

What the tests in this package prove about these files, and what they do not:

- `binary_test.go`, `binary_rules_test.go`, `socket_test.go`,
  `headers_test.go` and `tls_binary_test.go` run the real agentgateway v1.6.0
  binary in `--validate-only` mode over every file; `with_tls` is validated
  with its three paths pointed at files that exist, because the binary opens
  them (below). That proves the YAML shape, the CEL
  syntax of the allow rules and of the secret literals, that the `config`
  listener addresses and `bindAddress` parse (host names, host:port forms,
  brackets, zones and the empty string are refused as IPs; an IPv6 listener
  needs brackets; `off` is case-sensitive and unpadded), that every route's
  `gateways` reference resolves, that the gateway refuses the server names
  (`_`, a leading or trailing `-`) and the URL characters (`"`, `<`, `>`,
  space) the emitter refuses, that a raw `$NAME` anywhere in the file, comments
  included, is looked up in the gateway's environment, that the escaped forms
  the emitter writes are accepted, and that the request-header filter is read
  as two lists of header names (a scalar, an unknown key, an invalid name and
  an unknown pseudo-header are refused, `TestGatewayParsesTheRequestHeaderFilter`),
  and that the `backendTLS` block is read: `--validate-only` opens the
  block's three files and refuses a path it cannot open with `read resource
  file PATH` (so `emit --gateway-binary` needs the files on the emitting
  host), parses the certificate and the key (`no certificate`, `no key`) but
  not the root bundle (a file of garbage there validates), refuses an unknown
  field naming the ten the schema has, and refuses a hostname that is not a
  DNS name or an IP literal (`invalid dns name`: empty, bracketed, `host:port`,
  the resolver's numeric shorthand); it accepts a block without `cert` and
  `key`, without a hostname, with an IPv4 or IPv6 literal as hostname, and an
  empty block, each of which the emitter refuses on its own account
  (`TestGatewayValidateOnlyOpensBackendTLSFiles`, `TestGatewayParsesBackendTLS`).
  It proves nothing about runtime semantics: `--validate-only` accepts unknown
  CEL variables (`mcp.tool.nmae`), type errors (`mcp.tool.name == 5`),
  non-boolean rules, empty and deny-only rule sets, `failOpen`, unknown method
  names, duplicate route names, two listeners on one port, a processor address
  that is one of the gateway's own sockets
  (`TestGatewayAcceptsAProcessorOnItsOwnSocket`), a processor host in a numeric
  spelling the resolver reads as loopback (`127.1`, `0x7f.0.0.1`, `2130706433`;
  `TestGatewayAcceptsAmbiguousProcessorSpellings`), bind addresses that cannot
  be bound at start-up (`::ffff:127.0.0.1`, `224.0.0.1`, `255.255.255.255`,
  `fe80::1` without a zone), a dot or 64 bytes in a server name, and `|`, `^`,
  `{`, `}`, backslash and backtick in a URL, which is why the emitter refuses
  those itself.
- That the sockets are really bound to those addresses, that `off` really
  starts no admin listener, that the routes attached by name are served, which
  methods the allow rule filters at runtime, that `mcp.tool.name` binds to the
  served tool name, that the processor really receives `toolwarrant_secret`,
  which headers the gateway puts on the wire towards the processor (by the
  gateway's module source, `:method` and nothing else), and whether the
  gateway completes a TLS handshake with a processor from the `backendTLS`
  block, presenting the certificate at `cert` and verifying the processor
  under `hostname`, are verified only by the end-to-end test (package `e2e`,
  gateway running as a server against a mock upstream; the handshake by
  scenario Q, not landed yet), not here. The emitted file is defence in depth
  behind the processor; the processor is the guard.
- `integrity_test.go` checks that every file here verifies with `emit.Verify`,
  so a hand edit of a golden file fails the suite the same way an edited
  deployed config fails the operator's canary. `TestVerifyIsUnkeyed` pins the
  limit of that check: a file whose hash line was recomputed verifies, and only
  a comparison with the recorded body hash tells it apart.
