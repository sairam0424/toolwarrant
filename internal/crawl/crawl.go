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
// Everything the server sends is hostile. The client fails closed: a response
// it cannot read strictly (duplicate keys, invalid UTF-8, a tool without a
// name, a repeated cursor, too many pages or tools) ends the crawl with an
// error instead of returning a partial or guessed list. A crawl never
// approves anything; it only reports.
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
	"net/url"
)

const (
	// defaultMaxPages bounds how many tools/list pages one crawl may follow.
	defaultMaxPages = 100
	// defaultMaxTools bounds how many tools one crawl may collect.
	defaultMaxTools = 10000
	// defaultMaxMessageBytes caps one JSON-RPC message or one SSE event. It
	// matches the hardened fetch client's default response cap.
	defaultMaxMessageBytes = 8 << 20
	// defaultClientName and defaultClientVersion identify this client to the
	// upstream when the caller does not say otherwise.
	defaultClientName    = "toolwarrant"
	defaultClientVersion = "dev"
	// requestedProtocolVersion is the MCP revision this client speaks.
	requestedProtocolVersion = "2025-06-18"
	// maxCursorBytes caps a server-supplied pagination cursor, which is sent
	// back to the server verbatim and remembered for loop detection.
	maxCursorBytes = 8 << 10
	// maxToolNameBytes caps a tool name; the name becomes a store key.
	maxToolNameBytes = 1 << 10
)

// Sentinel errors a caller can test with errors.Is. Each is wrapped with
// detail, never returned bare.
var (
	// ErrTooManyPages means the server kept offering a next page after
	// MaxPages pages. A bound stops an endless or hostile listing.
	ErrTooManyPages = errors.New("crawl: too many tools/list pages")
	// ErrTooManyTools means the server listed more than MaxTools tools.
	ErrTooManyTools = errors.New("crawl: too many tools")
	// ErrCursorLoop means the server handed back a cursor it had already
	// handed back, so following it would never end.
	ErrCursorLoop = errors.New("crawl: pagination cursor repeated")
	// ErrDuplicateTool means two tools shared a name. The catalog keys tools
	// by name, so a duplicate cannot be recorded faithfully.
	ErrDuplicateTool = errors.New("crawl: duplicate tool name")
	// ErrMalformed means the server sent something that is not valid MCP
	// for this purpose: bad JSON, a wrong shape, an unusable tool.
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
	// MaxTools bounds the tools collected; zero means 10000.
	MaxTools int
	// MaxMessageBytes caps one JSON-RPC message or SSE event; zero means
	// 8 MiB. The Client still enforces the cap on the whole body.
	MaxMessageBytes int
	// ClientName and ClientVersion identify this client in initialize.
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
	// Tools are all tools, in server order, with duplicates rejected.
	Tools []Tool
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

// config is Options with defaults applied and the endpoint validated.
type config struct {
	endpoint      string
	client        *http.Client
	headers       http.Header
	maxPages      int
	maxTools      int
	maxMessage    int
	clientName    string
	clientVersion string
}

// newConfig validates endpoint and opt and applies defaults. It never puts
// the endpoint in an error because it may carry credentials in its query.
func newConfig(endpoint string, opt Options) (config, error) {
	if opt.Client == nil {
		return config{}, fmt.Errorf("%w: Client is required", ErrInvalidOptions)
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return config{}, fmt.Errorf("%w: endpoint must be an absolute http or https URL", ErrInvalidOptions)
	}
	if opt.MaxPages < 0 || opt.MaxTools < 0 || opt.MaxMessageBytes < 0 {
		return config{}, fmt.Errorf("%w: limits must not be negative", ErrInvalidOptions)
	}
	headers := http.Header{}
	for k, v := range opt.Headers {
		key := http.CanonicalHeaderKey(k)
		if isProtocolHeader(key) {
			continue
		}
		headers[key] = append([]string(nil), v...)
	}
	return config{
		endpoint:      endpoint,
		client:        opt.Client,
		headers:       headers,
		maxPages:      orDefault(opt.MaxPages, defaultMaxPages),
		maxTools:      orDefault(opt.MaxTools, defaultMaxTools),
		maxMessage:    orDefault(opt.MaxMessageBytes, defaultMaxMessageBytes),
		clientName:    orDefaultString(opt.ClientName, defaultClientName),
		clientVersion: orDefaultString(opt.ClientVersion, defaultClientVersion),
	}, nil
}

// isProtocolHeader reports whether key is a header this package owns. A
// caller's value for it is dropped so that it can neither forge a session nor
// change how the body is framed.
func isProtocolHeader(key string) bool {
	switch key {
	case "Content-Type", "Accept", "Content-Length", http.CanonicalHeaderKey(headerSessionID), http.CanonicalHeaderKey(headerProtocol):
		return true
	}
	return false
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func orDefaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ListTools connects to the MCP server at endpoint, lists all of its tools
// and returns each as the bytes the server sent. It opens a session, follows
// pagination to the end, and ends the session on a best-effort basis.
//
// It returns an error, and no partial result, if anything about the
// conversation is wrong. The error never contains header values or request
// bodies.
func ListTools(ctx context.Context, endpoint string, opt Options) (Result, error) {
	cfg, err := newConfig(endpoint, opt)
	if err != nil {
		return Result{}, err
	}
	s := newSession(cfg)
	info, err := s.initialize(ctx)
	if err != nil {
		return Result{}, err
	}
	defer s.end(ctx)
	if err := s.notifyInitialized(ctx); err != nil {
		return Result{}, err
	}
	tools, pages, err := s.listAll(ctx)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Tools:           tools,
		Pages:           pages,
		ServerName:      info.name,
		ServerVersion:   info.version,
		ProtocolVersion: s.protocol,
	}, nil
}

// listAll walks tools/list to the end, enforcing every bound.
func (s *session) listAll(ctx context.Context) ([]Tool, int, error) {
	tools := []Tool{}
	names := map[string]struct{}{}
	cursors := map[string]struct{}{}
	cursor := ""
	for pages := 1; ; pages++ {
		if err := ctx.Err(); err != nil {
			return nil, 0, fmt.Errorf("crawl: tools/list: %w", err)
		}
		result, _, err := s.call(ctx, methodToolsList, toolsListParams{Cursor: cursor})
		if err != nil {
			return nil, 0, err
		}
		raws, next, err := parseToolsPage(result)
		if err != nil {
			return nil, 0, err
		}
		for _, raw := range raws {
			if len(tools) >= s.cfg.maxTools {
				return nil, 0, fmt.Errorf("%w: more than %d", ErrTooManyTools, s.cfg.maxTools)
			}
			name, err := parseToolName(raw)
			if err != nil {
				return nil, 0, err
			}
			if _, dup := names[name]; dup {
				return nil, 0, fmt.Errorf("%w: %q", ErrDuplicateTool, name)
			}
			names[name] = struct{}{}
			tools = append(tools, Tool{Name: name, Raw: raw})
		}
		if next == "" {
			return tools, pages, nil
		}
		if _, seen := cursors[next]; seen {
			return nil, 0, ErrCursorLoop
		}
		cursors[next] = struct{}{}
		if pages >= s.cfg.maxPages {
			return nil, 0, fmt.Errorf("%w: more than %d", ErrTooManyPages, s.cfg.maxPages)
		}
		cursor = next
	}
}
