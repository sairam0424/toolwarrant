// Package api holds the Go stubs for agentgateway's ExtMCP gRPC protocol,
// generated from third_party/agentgateway/ext_mcp.proto, an unmodified copy
// of crates/protos/proto/ext_mcp.proto at agentgateway v1.6.0 (see the NOTICE
// next to it).
//
// The package is named api because the proto's go_package option names it so;
// toolwarrant imports it by directory, internal/extmcpv1, where v1 pins the
// gateway release the proto was taken from. internal/processor speaks this
// protocol. Nothing in this package is hand-written except this file.
//
// Regeneration is deliberate, never implicit: the generated files are
// committed so that a build needs no protoc, and scripts/gen-proto.sh accepts
// only the protoc, protoc-gen-go and protoc-gen-go-grpc versions recorded in
// the generated headers, because another generator version changes the output
// and would hide a real protocol change in a noisy diff. After updating the
// proto copy run
//
//	go generate ./internal/extmcpv1
//
// and review the diff; scripts/gen-proto.sh --check verifies without writing.
package api

//go:generate bash ../../scripts/gen-proto.sh
