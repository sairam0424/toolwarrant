// Package crawl is a minimal raw MCP Streamable HTTP client that lists every
// tool of a remote server and hands each tool back as the exact bytes the
// server sent.
//
// Why not the go-sdk client: it decodes tool definitions into Go types, which
// drops unknown fields and rewrites numbers and key order. toolwarrant's
// approvals are bound to a digest of the definition, so a crawl must record
// what the upstream really said. Tools therefore stay json.RawMessage from the
// socket to the caller.
//
// Everything the server sends is hostile. The conversation fails closed: a
// response the client cannot read strictly (invalid UTF-8, duplicate keys in a
// message, a result without a tools array, a repeated cursor, too many pages,
// too many tools, too many bytes in total, a crawl that outlives its deadline)
// ends the crawl with an error instead of returning a partial or guessed list.
// Invalid UTF-8 anywhere in a message, inside a tool included, is a malformed
// message: JSON is defined over UTF-8 and the message is the unit the grammar
// defines, so it is refused before any tool is looked at. A failed crawl is
// recorded as a failure by the caller, and an upstream that wants a crawl to
// fail can always fail it (a 500 does); that is why a call is protected by the
// processor's own check of the live listing, not by the crawl.
//
// One bad tool does not end the crawl, though. The crawler applies to every
// listed tool exactly the rules the digest (internal/gate) and the catalog
// apply later: the shared tool-name rule (internal/toolname), a size cap, a
// nesting cap, and RFC 8785 canonicalisation as internal/gate applies it,
// which refuses lone surrogate escapes, numbers that IEEE 754 double precision
// cannot hold exactly and duplicate keys at any depth. A
// tool that breaks a rule, and every copy of a name that is listed more than
// once, is reported in Result.Unusable instead of Result.Tools, so that the
// catalog can veto serving that name instead of treating the tool as absent.
// Before this, a single decoy tool passed the crawl and made the catalog
// refuse the whole crawl, which froze the evidence protecting an approved tool
// while the upstream served something else for it.
//
// A crawl never approves anything; it only reports.
//
// Known limits. An upstream can tell the crawler apart from the gateway: the
// default clientInfo is neutral, but request shape, timing and source address
// identify a crawler, so an upstream can show the crawler the approved
// definition and the gateway another one. The processor's check of the live
// listing at list and call time is the defence against that, not the crawl. A
// listed value that is not parseable JSON has no name to report; it appears in
// Result.Unusable without one.
//
// Credentials in Options.Headers are added to every request and are never
// copied into an error. The package does no logging.
package crawl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	// defaultMaxPages bounds how many tools/list pages one crawl may follow.
	defaultMaxPages = 100
	// defaultMaxTools bounds how many tools one crawl may collect, usable or
	// not.
	defaultMaxTools = 10000
	// defaultMaxMessageBytes caps one JSON-RPC message or one SSE event. It
	// matches the hardened fetch client's default response cap.
	defaultMaxMessageBytes = 8 << 20
	// defaultMaxToolBytes caps one tool definition. It is the catalog's cap, so
	// that nothing the crawler calls usable is refused later for its size.
	defaultMaxToolBytes = 256 << 10
	// defaultMaxTotalBytes caps what one crawl retains across all pages. Each
	// page is bounded on its own, but without a total a hostile server could
	// make one crawl hold MaxPages x MaxMessageBytes, 800 MiB by default.
	defaultMaxTotalBytes = 32 << 20
	// defaultTimeout bounds a whole crawl. The HTTP client bounds one request,
	// so a server that stalls on every page could otherwise hold a crawl for
	// MaxPages times the client's timeout.
	defaultTimeout = 5 * time.Minute
	// maxToolDepth bounds how deep arrays and objects nest inside one tool,
	// counting the tool object itself as level 1. Real schemas nest a handful
	// of levels; deep nesting is a parser attack.
	maxToolDepth = 32
	// defaultClientName and defaultClientVersion are the clientInfo sent when
	// the caller does not say otherwise. They are deliberately generic: a
	// crawler that announces itself invites an upstream to show it a
	// different definition than it shows the gateway.
	defaultClientName    = "mcp-client"
	defaultClientVersion = "0.1.0"
	// requestedProtocolVersion is the MCP revision this client speaks.
	requestedProtocolVersion = "2025-06-18"
	// maxCursorBytes caps a server-supplied pagination cursor, which is sent
	// back to the server verbatim and remembered for loop detection.
	maxCursorBytes = 8 << 10
)

// Sentinel errors a caller can test with errors.Is. Each is wrapped with
// detail, never returned bare.
var (
	// ErrTooManyPages means the server kept offering a next page after
	// MaxPages pages. A bound stops an endless or hostile listing.
	ErrTooManyPages = errors.New("crawl: too many tools/list pages")
	// ErrTooManyTools means the server listed more than MaxTools tools.
	ErrTooManyTools = errors.New("crawl: too many tools")
	// ErrTooLarge means the tool definitions listed so far, usable or not,
	// exceed MaxTotalBytes. The crawl stops there: a result that large would
	// be refused by the catalog anyway, and holding it would let one server
	// exhaust the control plane's memory.
	ErrTooLarge = errors.New("crawl: tool definitions exceed the total byte budget")
	// ErrCursorLoop means the server handed back a cursor it had already
	// handed back, so following it would never end.
	ErrCursorLoop = errors.New("crawl: pagination cursor repeated")
	// ErrDuplicateTool is not returned any more. A name listed more than once
	// makes every copy unusable (ReasonDuplicateName) and the crawl goes on,
	// so that the catalog still learns about every other tool. The sentinel
	// stays so that callers which classify crawl errors keep compiling; they
	// should drop the reference.
	ErrDuplicateTool = errors.New("crawl: duplicate tool name")
	// ErrMalformed means the server sent something that is not valid MCP for
	// this purpose: bad JSON, invalid UTF-8, a wrong shape, an unusable cursor
	// or session id. One malformed tool is not malformed MCP: it is reported
	// in Result.Unusable instead.
	ErrMalformed = errors.New("crawl: malformed server response")
	// ErrInvalidOptions means the endpoint or Options cannot be used.
	ErrInvalidOptions = errors.New("crawl: invalid options")
)

// HTTPStatusError is returned when the server answers a request with a
// non-success HTTP status. It carries only the status so that no header or
// body, which may hold credentials, can leak through an error string.
type HTTPStatusError struct {
	// Status is the HTTP status code.
	Status int
}

// Error implements error.
func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("crawl: unexpected HTTP status %d", e.Status)
}

// RPCError is returned when the server answers with a JSON-RPC error object.
// Message is server-controlled text, trimmed of control characters and
// length-capped before it reaches a caller.
type RPCError struct {
	// Code is the JSON-RPC error code.
	Code int
	// Message is the sanitised server-supplied message.
	Message string
}

// Error implements error.
func (e *RPCError) Error() string {
	return fmt.Sprintf("crawl: server returned JSON-RPC error %d: %s", e.Code, e.Message)
}

// Options configures ListTools.
type Options struct {
	// Client sends every request. It is required. In production it is the
	// hardened client from internal/fetch, which owns the SSRF policy, the
	// redirect policy and the overall response cap.
	Client *http.Client
	// Headers are added to every request, for example Authorization. They are
	// never copied into an error. Protocol headers set by this package win.
	Headers http.Header
	// MaxPages bounds the tools/list pages followed; zero means 100.
	MaxPages int
	// MaxTools bounds the tools collected, usable or not; zero means 10000.
	MaxTools int
	// MaxMessageBytes caps one JSON-RPC message or SSE event; zero means
	// 8 MiB. The Client still enforces the cap on the whole body.
	MaxMessageBytes int
	// MaxToolBytes caps one tool definition; a longer one is reported as
	// unusable, not hashed. Zero means 256 KiB, the catalog's cap.
	MaxToolBytes int
	// MaxTotalBytes caps the definitions one crawl retains across all pages,
	// usable and unusable; over it the crawl fails with ErrTooLarge. Zero
	// means 32 MiB.
	MaxTotalBytes int
	// Timeout bounds the whole crawl, every page included; zero means five
	// minutes. The Client's own timeout bounds one request only. The caller's
	// context can still end the crawl sooner.
	Timeout time.Duration
	// ClientName and ClientVersion are sent as clientInfo in initialize. They
	// default to a neutral name so that the crawler does not announce itself;
	// the package comment says why that is only a partial measure.
	ClientName    string
	ClientVersion string
}

// Tool is one tool exactly as the server sent it.
type Tool struct {
	// Name is the tool's "name" member.
	Name string
	// Raw is the tool object's bytes, unmodified, so a digest over it matches
	// what the upstream really served.
	Raw json.RawMessage
}

// Result is a completed crawl.
type Result struct {
	// Tools are the usable tools, in server order: each has a name that
	// passes the shared rule, fits the caps and canonicalises, and no other
	// listed tool shares its name.
	Tools []Tool
	// Unusable are the listed tools that broke a rule, in server order, each
	// with the rule it broke. They are reported, not dropped, so that the
	// catalog can mark the name as unusable rather than treat it as absent.
	Unusable []UnusableTool
	// Pages is the number of tools/list requests made.
	Pages int
	// ServerName and ServerVersion come from the initialize result's
	// serverInfo, sanitised. They are informational only.
	ServerName    string
	ServerVersion string
	// ProtocolVersion is the version the server negotiated and that was sent
	// as MCP-Protocol-Version on later requests.
	ProtocolVersion string
}

// ListTools connects to the MCP server at endpoint, lists all of its tools
// and returns each as the bytes the server sent. It opens a session, follows
// pagination to the end within Options.Timeout, and ends the session on a
// best-effort basis.
//
// It returns an error, and no partial result, if anything about the
// conversation is wrong. A tool that breaks a rule is not a wrong
// conversation: it is reported in Result.Unusable and the crawl is complete.
// The error never contains header values or request bodies.
func ListTools(ctx context.Context, endpoint string, opt Options) (Result, error) {
	cfg, err := newConfig(endpoint, opt)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	s := newSession(cfg)
	info, err := s.initialize(ctx)
	if err != nil {
		return Result{}, err
	}
	defer s.end(ctx)
	if err := s.notifyInitialized(ctx); err != nil {
		return Result{}, err
	}
	list, pages, err := s.listAll(ctx)
	if err != nil {
		return Result{}, err
	}
	tools, unusable := finish(list)
	return Result{
		Tools:           tools,
		Unusable:        unusable,
		Pages:           pages,
		ServerName:      info.name,
		ServerVersion:   info.version,
		ProtocolVersion: s.protocol,
	}, nil
}
