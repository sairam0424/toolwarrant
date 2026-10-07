//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// rawSession is a minimal MCP Streamable HTTP client that keeps the bytes the
// gateway serves. The go-sdk client decodes tools into Go types and drops the
// keys it does not know, which is exactly the information scenario L needs:
// which keys the gateway itself dropped. It handles both response shapes the
// gateway uses, a single JSON message and an event stream.
type rawSession struct {
	url      string
	session  string
	protocol string
	next     int
	client   *http.Client
}

// rpcError is a JSON-RPC error object as the gateway returns it.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("json-rpc error %d: %s", e.Code, e.Message) }

const rawMaxBody = 8 << 20

// openRaw initialises a new session at url.
func openRaw(t *testing.T, url string) *rawSession {
	t.Helper()
	r := &rawSession{url: url, client: &http.Client{Timeout: opTimeout}}
	params := map[string]any{"protocolVersion": defaultProtocol, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "toolwarrant-e2e-raw", "version": "0.0.1"}}
	result, header, err := r.call("initialize", params)
	if err != nil {
		t.Fatalf("raw initialize at %s: %v", url, err)
	}
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(result, &init); err != nil {
		t.Fatalf("raw initialize result: %v", err)
	}
	r.session, r.protocol = header.Get("Mcp-Session-Id"), init.ProtocolVersion
	if err := r.notify("notifications/initialized"); err != nil {
		t.Fatalf("raw notifications/initialized: %v", err)
	}
	return r
}

// listRaw returns every tool of one tools/list page as the gateway sent it.
func (r *rawSession) listRaw(t *testing.T) []json.RawMessage {
	t.Helper()
	result, _, err := r.call("tools/list", map[string]any{})
	if err != nil {
		t.Fatalf("raw tools/list: %v", err)
	}
	var page struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(result, &page); err != nil {
		t.Fatalf("raw tools/list result: %v\n%s", err, result)
	}
	return page.Tools
}

// call sends one request and returns the matching result, or the JSON-RPC
// error the server answered with.
func (r *rawSession) call(method string, params any) (json.RawMessage, http.Header, error) {
	r.next++
	id := r.next
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, nil, err
	}
	resp, err := r.post(body)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, rawMaxBody))
	if err != nil {
		return nil, nil, err
	}
	result, rpcErr, found := findResponse(resp.Header.Get("Content-Type"), data, id)
	switch {
	case rpcErr != nil:
		return nil, resp.Header, rpcErr
	case found:
		return result, resp.Header, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, resp.Header, fmt.Errorf("http status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil, resp.Header, fmt.Errorf("no response to request %d in %q", id, data)
}

// notify sends a notification and expects 200 or 202.
func (r *rawSession) notify(method string) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	if err != nil {
		return err
	}
	resp, err := r.post(body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (r *rawSession) post(body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if r.session != "" {
		req.Header.Set("Mcp-Session-Id", r.session)
	}
	if r.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", r.protocol)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	// The body must be read before the context ends; copy it now.
	data, err := io.ReadAll(io.LimitReader(resp.Body, rawMaxBody))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return resp, nil
}

// findResponse looks for the message answering request id in a JSON body or
// in the data lines of an event stream.
func findResponse(contentType string, data []byte, id int) (json.RawMessage, *rpcError, bool) {
	candidates := [][]byte{data}
	if strings.HasPrefix(contentType, "text/event-stream") {
		candidates = nil
		for _, line := range strings.Split(string(data), "\n") {
			if payload, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "data:"); ok {
				candidates = append(candidates, []byte(strings.TrimSpace(payload)))
			}
		}
	}
	for _, c := range candidates {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if err := json.Unmarshal(c, &msg); err != nil {
			continue
		}
		if string(bytes.TrimSpace(msg.ID)) != fmt.Sprint(id) && msg.Error == nil {
			continue
		}
		if msg.Error != nil {
			return nil, msg.Error, true
		}
		return msg.Result, nil, true
	}
	return nil, nil, false
}

// sortStrings sorts in place; it exists so helpers that build lists for
// messages do not each import sort.
func sortStrings(s []string) { sort.Strings(s) }
