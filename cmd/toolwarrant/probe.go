package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The probe's wire details. The protocol version, client name and version
// are the crawler's, so that an upstream cannot tell the probe from a crawl
// by its initialize request.
const (
	// probeToolPrefix starts the tool name of every probe; the random suffix
	// keeps it from colliding with a real tool and from being cached. No
	// catalog can hold the name, so an id'd call for it is always denied.
	probeToolPrefix      = "toolwarrant.probe."
	probeSuffixBytes     = 4
	probeMaxBody         = 1 << 20
	probeRequestTimeout  = 30 * time.Second
	probeEndTimeout      = 3 * time.Second
	jsonrpcVersion       = "2.0"
	probeProtocolVersion = "2025-06-18"
	probeClientName      = "mcp-client"
	probeClientVersion   = "0.1.0"
	methodInitialize     = "initialize"
	methodInitialized    = "notifications/initialized"
	methodToolsCall      = "tools/call"
	mcpSessionHeader     = "Mcp-Session-Id"
	mcpProtocolHeader    = "MCP-Protocol-Version"
	mediaJSON            = "application/json"
	mediaSSE             = "text/event-stream"
	acceptMedia          = mediaJSON + ", " + mediaSSE
	sseDataPrefix        = "data:"
	// utf8BOM is the byte-order mark some writers put before a JSON text; the
	// JSON grammar does not allow it, so json.Valid refuses the text until
	// it is stripped (seventh review canary-2, D17 h).
	utf8BOM           = "\ufeff"
	maxHeaderValueLen = 1024
	initializeID      = 1
)

// rpcMessage is a JSON-RPC 2.0 message; an ID of zero is omitted, which makes
// the message a notification.
type rpcMessage struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// rawResponse is one HTTP answer of the gateway, body bounded and read.
type rawResponse struct {
	status      int
	header      http.Header
	contentType string
	body        []byte
}

// rawSession is the minimal MCP Streamable HTTP client the probe needs: one
// initialize, the initialized notification, the probe itself and the DELETE
// that ends the session. The crawl package's session is not reused because
// it only speaks requests with ids, and the probe's whole point is a message
// without one.
type rawSession struct {
	client   *http.Client
	url      string
	headers  http.Header
	session  string
	protocol string
}

// probeUnhookedCalls opens a fresh MCP session at url, sends one tools/call
// WITHOUT an id (a JSON-RPC notification) for a tool name no catalog can
// hold, and reports what came back. agentgateway v1.6.0 accepts such a
// message as a notification (HTTP 202), forwards it to the upstream and runs
// neither the ExtMCP processor nor the mcpAuthorization rule for it (second
// review, system finding; known limit L17), so a 202 means every tools/call
// in that shape bypasses the approval. That is the one thing the probe
// proves. Any other answer proves nothing about the hook (D17 h): a gateway
// that forwards the call and relays the upstream's answer looks exactly like
// one that refused the call itself, so the probe attributes nothing it cannot
// attribute. The probe reaches the upstream exactly when the gateway is
// vulnerable.
func probeUnhookedCalls(ctx context.Context, client *http.Client, url string, headers http.Header) (probeReport, error) {
	s := &rawSession{client: client, url: url, headers: headers}
	if err := s.initialize(ctx); err != nil {
		return probeReport{}, fmt.Errorf("unhooked-call probe: %w", err)
	}
	defer s.end(ctx)
	name, err := probeToolName()
	if err != nil {
		return probeReport{}, fmt.Errorf("unhooked-call probe: %w", err)
	}
	params := map[string]any{"name": name, "arguments": map[string]any{}}
	resp, err := s.post(ctx, rpcMessage{JSONRPC: jsonrpcVersion, Method: methodToolsCall, Params: params})
	if err != nil {
		return probeReport{}, fmt.Errorf("unhooked-call probe: %w", err)
	}
	outcome, err := classifyProbe(resp)
	return probeReport{outcome: outcome, status: resp.status}, err
}

// probeToolName is probeToolPrefix plus a random hex suffix.
func probeToolName() (string, error) {
	b := make([]byte, probeSuffixBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random suffix: %w", err)
	}
	return probeToolPrefix + hex.EncodeToString(b), nil
}

// classifyProbe turns the answer to the id-less tools/call into a verdict
// (D13 h, D14 i, D15 k, D17 h): 202 forwarded it (UNHOOKED-CALLS); a 400 whose
// body carries JSON, or that was cut at the read cap, is inconclusive, because
// a forwarding gateway relays an upstream's JSON-RPC refusal, single or
// batched, in the body or across the data lines of one event, after a
// byte-order mark or longer than the cap, and so it may be the upstream's
// answer; any other 400 is reported as not accepted as a notification by the
// gateway or by the upstream, which passes the check and proves nothing about
// the hook: until the seventh review such a 400 was called the gateway's own
// refusal, although a forwarding gateway relays a plain-text refusal just as
// well (canary-1); any other 2xx that carries a body is inconclusive for the
// same reason; a 2xx without a body and every other status is an error, since
// the probe then proved nothing either way, and the error says whether the
// answer carried a body.
func classifyProbe(resp rawResponse) (probeOutcome, error) {
	switch {
	case resp.status == http.StatusAccepted:
		return probeUnhooked, nil
	case resp.status == http.StatusBadRequest && (resp.truncated() || resp.carriesJSONAnswer()):
		return probeInconclusive, nil
	case resp.status == http.StatusBadRequest:
		return probeNotAccepted, nil
	case resp.status/100 == 2 && len(resp.body) > 0:
		return probeInconclusive, nil
	}
	return probeSkipped, fmt.Errorf("unhooked-call probe: the gateway answered http status %d %s, so whether it forwards id-less calls is unknown", resp.status, resp.bodyPhrase())
}

// bodyPhrase says whether and how large a body the answer carried, for an
// error line; the body itself is never shown.
func (r rawResponse) bodyPhrase() string {
	if len(r.body) == 0 {
		return "without a body"
	}
	return fmt.Sprintf("with a body of %d bytes", len(r.body))
}

// probeMaxBodyText is the read cap as the help text and the verdicts name it.
func probeMaxBodyText() string { return strconv.Itoa(probeMaxBody>>20) + " MiB" }

// truncated reports whether the body reached the read cap: the reader stops
// there, so a JSON answer longer than the cap arrives as invalid JSON and a
// body of that size proves nothing about what it was (canary-2, D17 h).
func (r rawResponse) truncated() bool {
	return len(r.body) >= probeMaxBody
}

// carriesJSONAnswer reports whether any message in the answer (the body, or
// the joined data lines of each event of an event stream) is JSON: a JSON-RPC
// answer is a JSON object or, batched, an array of them, and a 400 that
// carries one may be an upstream's refusal relayed by a forwarding gateway
// (D15 k). Until the fifth review only an object with an error member
// counted, so a batch of errors passed as the gateway's own refusal; until
// the seventh an event split over two data lines and a text behind a
// byte-order mark passed too (canary-2). Every JSON value counts, a bare
// scalar included, because the probe cannot tell who wrote it and must fail
// closed.
func (r rawResponse) carriesJSONAnswer() bool {
	for _, m := range r.messages() {
		if json.Valid(bytes.TrimSpace(bytes.TrimPrefix(m, []byte(utf8BOM)))) {
			return true
		}
	}
	return false
}

// initialize opens the session and records the negotiated protocol version
// and the session id, then sends notifications/initialized.
func (s *rawSession) initialize(ctx context.Context) error {
	params := map[string]any{
		"protocolVersion": probeProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": probeClientName, "version": probeClientVersion},
	}
	resp, err := s.post(ctx, rpcMessage{JSONRPC: jsonrpcVersion, ID: initializeID, Method: methodInitialize, Params: params})
	if err != nil {
		return err
	}
	if resp.status != http.StatusOK {
		return fmt.Errorf("http status %d on initialize", resp.status)
	}
	result, found := findResult(resp.messages(), initializeID)
	if !found {
		return errors.New("no initialize result in the gateway's answer")
	}
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(result, &init); err != nil || !headerValueOK(init.ProtocolVersion) || init.ProtocolVersion == "" {
		return errors.New("initialize result has no usable protocol version")
	}
	if id := resp.header.Get(mcpSessionHeader); !headerValueOK(id) {
		return errors.New("unusable session id")
	}
	s.protocol, s.session = init.ProtocolVersion, resp.header.Get(mcpSessionHeader)
	resp, err = s.post(ctx, rpcMessage{JSONRPC: jsonrpcVersion, Method: methodInitialized})
	if err != nil {
		return err
	}
	if resp.status != http.StatusOK && resp.status != http.StatusAccepted {
		return fmt.Errorf("http status %d on %s", resp.status, methodInitialized)
	}
	return nil
}

// headerValueOK accepts a value the probe will echo in a request header:
// printable ASCII and bounded, so the gateway cannot smuggle a header through
// the probe's own requests.
func headerValueOK(v string) bool {
	return len(v) <= maxHeaderValueLen && isPrintableASCII(v)
}

// post sends one message and reads the bounded answer. Transport errors are
// reduced to their class: the raw text could carry the URL.
func (s *rawSession) post(ctx context.Context, msg rpcMessage) (rawResponse, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return rawResponse{}, fmt.Errorf("encode %s: %w", msg.Method, err)
	}
	resp, err := s.do(ctx, http.MethodPost, body)
	if err != nil {
		return rawResponse{}, fmt.Errorf("%s: %s", msg.Method, scrubCrawlError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, probeMaxBody))
	if err != nil {
		return rawResponse{}, fmt.Errorf("%s: %s", msg.Method, scrubCrawlError(err))
	}
	return rawResponse{status: resp.StatusCode, header: resp.Header, contentType: resp.Header.Get("Content-Type"), body: data}, nil
}

// do performs one request with the caller's headers first and the protocol
// headers last, so the protocol headers win.
func (s *rawSession) do(ctx context.Context, method string, body []byte) (*http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, probeRequestTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(rctx, method, s.url, reader)
	if err != nil {
		return nil, err
	}
	for k, vs := range s.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", mediaJSON)
	}
	req.Header.Set("Accept", acceptMedia)
	if s.session != "" {
		req.Header.Set(mcpSessionHeader, s.session)
	}
	if s.protocol != "" {
		req.Header.Set(mcpProtocolHeader, s.protocol)
	}
	resp, err := s.client.Do(req) //nolint:bodyclose // the caller closes it after reading
	if err != nil {
		return nil, err
	}
	// The body must be read before the request context ends; copy it now.
	data, err := io.ReadAll(io.LimitReader(resp.Body, probeMaxBody))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return resp, nil
}

// end deletes the session, best effort: a short timeout of its own and every
// error ignored. It is skipped when the caller's context is already finished.
func (s *rawSession) end(ctx context.Context) {
	if s.session == "" || ctx.Err() != nil {
		return
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeEndTimeout)
	defer cancel()
	resp, err := s.do(dctx, http.MethodDelete, nil)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// messages splits the answer into JSON-RPC messages: the body itself, or one
// message per event of an event stream. The SSE specification joins the data
// lines of one event with a newline and dispatches the event at the blank
// line, so a message split over two data lines is one message here too,
// not two fragments that neither parse (canary-2, D17 h).
func (r rawResponse) messages() [][]byte {
	mediatype, _, err := mime.ParseMediaType(r.contentType)
	if err != nil || mediatype != mediaSSE {
		return [][]byte{r.body}
	}
	var out [][]byte
	var data []string
	flush := func() {
		if len(data) > 0 {
			out = append(out, []byte(strings.TrimSpace(strings.Join(data, "\n"))))
			data = nil
		}
	}
	// The SSE specification strips one leading byte-order mark from the whole
	// stream before any line is read; without it the first "data:" line is
	// missed and a relayed refusal passes as a bare 400 (eighth review).
	for _, line := range strings.Split(strings.TrimPrefix(string(r.body), utf8BOM), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			flush()
			continue
		}
		if payload, ok := strings.CutPrefix(line, sseDataPrefix); ok {
			data = append(data, strings.TrimSpace(payload))
		}
	}
	flush()
	return out
}

// rpcEnvelope is the part of a JSON-RPC message the probe reads.
type rpcEnvelope struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// findResult returns the result of the message answering request id.
func findResult(messages [][]byte, id int) (json.RawMessage, bool) {
	want := fmt.Sprint(id)
	for _, m := range messages {
		var env rpcEnvelope
		if json.Unmarshal(m, &env) != nil || string(bytes.TrimSpace(env.ID)) != want || len(env.Result) == 0 {
			continue
		}
		return env.Result, true
	}
	return nil, false
}
