package crawl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"
)

const (
	methodInitialize  = "initialize"
	methodInitialized = "notifications/initialized"
	methodToolsList   = "tools/list"

	headerSessionID = "Mcp-Session-Id"
	headerProtocol  = "MCP-Protocol-Version"

	mediaJSON = "application/json"
	mediaSSE  = "text/event-stream"

	// endSessionTimeout bounds the best-effort DELETE that ends a session.
	endSessionTimeout = 3 * time.Second
)

// session is one MCP conversation with one server. It is not safe for
// concurrent use.
type session struct {
	cfg       config
	nextID    int
	sessionID string
	protocol  string
}

// toolsListParams is the params object of tools/list.
type toolsListParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int   `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

func newSession(cfg config) *session {
	return &session{cfg: cfg}
}

// initialize performs the initialize request and records the negotiated
// protocol version and the session id, if the server issued one.
func (s *session) initialize(ctx context.Context) (initInfo, error) {
	params := map[string]any{
		"protocolVersion": requestedProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": s.cfg.clientName, "version": s.cfg.clientVersion},
	}
	result, header, err := s.call(ctx, methodInitialize, params)
	if err != nil {
		return initInfo{}, err
	}
	info, err := parseInitResult(result)
	if err != nil {
		return initInfo{}, err
	}
	if id := header.Get(headerSessionID); id != "" {
		if !validSessionID(id) {
			return initInfo{}, fmt.Errorf("%w: unusable session id", ErrMalformed)
		}
		s.sessionID = id
	}
	s.protocol = info.protocol
	return info, nil
}

// notifyInitialized sends notifications/initialized and expects 200 or 202.
func (s *session) notifyInitialized(ctx context.Context) error {
	body, err := marshalRequest(0, methodInitialized, nil)
	if err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodPost, methodInitialized, body)
	if err != nil {
		return err
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("%w: status %d for %s", ErrMalformed, resp.StatusCode, methodInitialized)
	}
	return nil
}

// end deletes the session, best effort: it has a short timeout of its own and
// every error is ignored. It is skipped when the caller's context is already
// finished, because that caller wants to return now.
func (s *session) end(ctx context.Context) {
	if s.sessionID == "" || ctx.Err() != nil {
		return
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), endSessionTimeout)
	defer cancel()
	resp, err := s.do(dctx, http.MethodDelete, "session end", nil)
	if err != nil {
		return
	}
	closeBody(resp.Body)
}

// call sends one JSON-RPC request and returns the matching response's result
// together with the HTTP response headers.
func (s *session) call(ctx context.Context, method string, params any) (json.RawMessage, http.Header, error) {
	s.nextID++
	id := s.nextID
	body, err := marshalRequest(id, method, params)
	if err != nil {
		return nil, nil, err
	}
	resp, err := s.do(ctx, http.MethodPost, method, body)
	if err != nil {
		return nil, nil, err
	}
	defer closeBody(resp.Body)
	result, err := s.readResponse(resp, id)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", method, err)
	}
	return result, resp.Header, nil
}

// marshalRequest builds a JSON-RPC 2.0 message. id 0 means a notification,
// which has no id member.
func marshalRequest(id int, method string, params any) ([]byte, error) {
	msg := rpcRequest{JSONRPC: "2.0", Method: method, Params: params}
	if id != 0 {
		msg.ID = &id
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("crawl: encode %s request: %w", method, err)
	}
	return body, nil
}

// do sends one HTTP request and returns the response only if its status is
// 2xx. what names the operation for errors; it must not contain secrets.
func (s *session) do(ctx context.Context, httpMethod, what string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, httpMethod, s.cfg.endpoint, rdr)
	if err != nil {
		return nil, fmt.Errorf("crawl: build %s request: %w", what, withoutURL(err))
	}
	s.setHeaders(req, body != nil)
	resp, err := s.cfg.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crawl: %s request failed: %w", what, withoutURL(err))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		closeBody(resp.Body)
		return nil, &HTTPStatusError{Status: resp.StatusCode}
	}
	return resp, nil
}

// setHeaders applies the caller's headers first and the protocol headers
// after, so a caller cannot override the protocol.
func (s *session) setHeaders(req *http.Request, hasBody bool) {
	req.Header = s.cfg.headers.Clone()
	if hasBody {
		req.Header.Set("Content-Type", mediaJSON)
		req.Header.Set("Accept", mediaJSON+", "+mediaSSE)
	}
	if s.sessionID != "" {
		req.Header.Set(headerSessionID, s.sessionID)
	}
	if s.protocol != "" {
		req.Header.Set(headerProtocol, s.protocol)
	}
}

// readResponse extracts the JSON-RPC response to request id from an HTTP
// response that is either a single JSON message or an event stream.
func (s *session) readResponse(resp *http.Response, id int) (json.RawMessage, error) {
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("%w: missing or invalid Content-Type", ErrMalformed)
	}
	switch mediaType {
	case mediaJSON:
		return s.readJSON(resp.Body, id)
	case mediaSSE:
		return s.readStream(resp.Body, id)
	}
	return nil, fmt.Errorf("%w: unsupported Content-Type %q", ErrMalformed, sanitizeText(mediaType, maxErrorMessageBytes))
}

func (s *session) readJSON(body io.Reader, id int) (json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(body, int64(s.cfg.maxMessage)+1))
	if err != nil {
		return nil, fmt.Errorf("crawl: read response: %w", err)
	}
	if len(data) > s.cfg.maxMessage {
		return nil, fmt.Errorf("%w: response longer than %d bytes", ErrMalformed, s.cfg.maxMessage)
	}
	result, matched, err := matchMessage(data, id)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, fmt.Errorf("%w: response does not answer the request", ErrMalformed)
	}
	return result, nil
}

// readStream reads events until the one that answers request id, skipping
// comments, notifications and messages for other ids.
func (s *session) readStream(body io.Reader, id int) (json.RawMessage, error) {
	var (
		result json.RawMessage
		found  bool
	)
	err := readSSE(body, s.cfg.maxMessage, func(ev sseEvent) (bool, error) {
		if (ev.Event != "" && ev.Event != "message") || len(bytes.TrimSpace(ev.Data)) == 0 {
			return false, nil
		}
		r, matched, err := matchMessage(ev.Data, id)
		if err != nil {
			return true, err
		}
		result, found = r, matched
		return matched, nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: event stream ended without a response", ErrMalformed)
	}
	return result, nil
}

// closeBody closes a response body without reading what is left of it. A
// hostile or stalled server could make a drain block, and a crawl is rare
// enough that losing connection reuse costs nothing.
func closeBody(body io.Closer) {
	_ = body.Close()
}

// withoutURL removes the request URL from a *url.Error. The endpoint may
// carry credentials in its query string or user info, and net/http puts the
// whole URL in its errors. The wrapped cause (context errors included) stays
// reachable through errors.Is and errors.As.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}
