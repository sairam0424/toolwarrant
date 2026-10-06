package crawl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// rpcErrorReply answers every POST whose method matches with a JSON-RPC error.
func rpcErrorReply(f *fake, method string, body string) {
	f.override = func(w http.ResponseWriter, _ *http.Request, in rpcIn) bool {
		if in.Method != method {
			return false
		}
		msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":%s}`, in.ID, body)
		writeMessage(w, f.mode, in.ID, msg, "")
		return true
	}
}

func TestRPCErrors(t *testing.T) {
	for name, mode := range map[string]replyMode{"json": modeJSON, "sse": modeSSE} {
		for _, method := range []string{methodInitialize, methodToolsList} {
			t.Run(name+"/"+method, func(t *testing.T) {
				f := newFake(t, mode, pagesOf(5, nTools(1)))
				rpcErrorReply(f, method, `{"code":-32602,"message":"bad\u0000 thing\nhere"}`)
				_, err := ListTools(context.Background(), f.url(), testOptions())
				var rpc *RPCError
				if !errors.As(err, &rpc) {
					t.Fatalf("err = %v, want *RPCError", err)
				}
				if rpc.Code != -32602 || rpc.Message != "bad  thing here" {
					t.Errorf("RPCError = %+v", rpc)
				}
			})
		}
	}
}

func TestRPCErrorMessageIsCapped(t *testing.T) {
	f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
	rpcErrorReply(f, methodInitialize, `{"code":1,"message":"`+strings.Repeat("é", 1000)+`"}`)
	_, err := ListTools(context.Background(), f.url(), testOptions())
	var rpc *RPCError
	if !errors.As(err, &rpc) || len(rpc.Message) > maxErrorMessageBytes {
		t.Fatalf("message not capped: %v", err)
	}
}

func TestRPCErrorWithNullID(t *testing.T) {
	f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
	f.override = func(w http.ResponseWriter, _ *http.Request, in rpcIn) bool {
		if in.Method != methodInitialize {
			return false
		}
		writeMessage(w, modeJSON, in.ID, `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`, "")
		return true
	}
	_, err := ListTools(context.Background(), f.url(), testOptions())
	var rpc *RPCError
	if !errors.As(err, &rpc) || rpc.Code != -32700 {
		t.Fatalf("err = %v, want *RPCError -32700", err)
	}
}

func TestHTTPStatusErrors(t *testing.T) {
	cases := []struct {
		name   string
		method string
		status int
	}{
		{"initialize 401", methodInitialize, http.StatusUnauthorized},
		{"initialize 500", methodInitialize, http.StatusInternalServerError},
		{"initialize 404", methodInitialize, http.StatusNotFound},
		{"notification 500", methodInitialized, http.StatusInternalServerError},
		{"tools/list 401", methodToolsList, http.StatusUnauthorized},
		{"tools/list 503", methodToolsList, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
			f.override = func(w http.ResponseWriter, _ *http.Request, in rpcIn) bool {
				if in.Method != tc.method {
					return false
				}
				http.Error(w, "nope: Bearer leaked-in-body", tc.status)
				return true
			}
			_, err := ListTools(context.Background(), f.url(), testOptions())
			var se *HTTPStatusError
			if !errors.As(err, &se) || se.Status != tc.status {
				t.Fatalf("err = %v, want HTTPStatusError %d", err, tc.status)
			}
			if strings.Contains(err.Error(), "leaked-in-body") {
				t.Errorf("response body leaked into error: %v", err)
			}
		})
	}
}

func TestNotificationStatusMustBe200Or202(t *testing.T) {
	for status, wantOK := range map[int]bool{http.StatusOK: true, http.StatusAccepted: true, http.StatusNoContent: false, http.StatusCreated: false} {
		f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
		f.override = func(w http.ResponseWriter, _ *http.Request, in rpcIn) bool {
			if in.Method == methodInitialized {
				w.WriteHeader(status)
				return true
			}
			return false
		}
		_, err := ListTools(context.Background(), f.url(), testOptions())
		if wantOK && err != nil {
			t.Errorf("notification status %d rejected: %v", status, err)
		}
		if !wantOK && !errors.Is(err, ErrMalformed) {
			t.Errorf("notification status %d: err = %v, want ErrMalformed", status, err)
		}
	}
}

func TestCursorLoop(t *testing.T) {
	cases := map[string]func(call int, cursor string) string{
		"immediate repeat": func(call int, _ string) string {
			return fmt.Sprintf(`{"tools":[%s],"nextCursor":"same"}`, toolJSON(call))
		},
		"cycle a-b-a": func(call int, _ string) string {
			cursors := []string{"a", "b", "a"}
			return fmt.Sprintf(`{"tools":[%s],"nextCursor":%q}`, toolJSON(call), cursors[(call-1)%3])
		},
	}
	for name, page := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, modeJSON, page)
			_, err := ListTools(context.Background(), f.url(), testOptions())
			if !errors.Is(err, ErrCursorLoop) {
				t.Fatalf("err = %v, want ErrCursorLoop", err)
			}
		})
	}
}

func TestTooManyPages(t *testing.T) {
	endless := func(call int, _ string) string {
		return fmt.Sprintf(`{"tools":[%s],"nextCursor":"cursor-%d"}`, toolJSON(call), call)
	}
	f := newFake(t, modeJSON, endless)
	opt := testOptions()
	opt.MaxPages = 3
	_, err := ListTools(context.Background(), f.url(), opt)
	if !errors.Is(err, ErrTooManyPages) {
		t.Fatalf("err = %v, want ErrTooManyPages", err)
	}
	if lists := countLists(f); lists != 3 {
		t.Errorf("made %d tools/list requests, want exactly MaxPages=3", lists)
	}
}

func TestMaxPagesBoundary(t *testing.T) {
	for maxPages, wantErr := range map[int]bool{4: false, 3: true} {
		f := newFake(t, modeJSON, pagesOf(2, nTools(7)))
		opt := testOptions()
		opt.MaxPages = maxPages
		res, err := ListTools(context.Background(), f.url(), opt)
		if wantErr != errors.Is(err, ErrTooManyPages) {
			t.Errorf("MaxPages=%d: err = %v", maxPages, err)
		}
		if !wantErr && res.Pages != 4 {
			t.Errorf("MaxPages=%d: pages = %d", maxPages, res.Pages)
		}
	}
}

func TestMaxToolsBoundary(t *testing.T) {
	for maxTools, wantErr := range map[int]bool{7: false, 6: true, 1: true} {
		f := newFake(t, modeJSON, pagesOf(3, nTools(7)))
		opt := testOptions()
		opt.MaxTools = maxTools
		res, err := ListTools(context.Background(), f.url(), opt)
		if wantErr != errors.Is(err, ErrTooManyTools) {
			t.Errorf("MaxTools=%d: err = %v", maxTools, err)
		}
		if wantErr && len(res.Tools) != 0 {
			t.Errorf("MaxTools=%d: a failed crawl returned %d tools", maxTools, len(res.Tools))
		}
	}
}

// TestMalformedListPages lists what makes a whole tools/list page, and so the
// crawl, malformed. One broken tool is not on this list any more: it is
// reported in Result.Unusable and the crawl completes (vet_test.go). Invalid
// UTF-8 stays here wherever it sits, because JSON is defined over UTF-8 and the
// message is the unit the grammar defines; see the package comment.
func TestMalformedListPages(t *testing.T) {
	longCursor := strings.Repeat("c", maxCursorBytes+1)
	cases := map[string]string{
		"duplicate key in result":    `{"tools":[],"tools":[]}`,
		"invalid UTF-8 in a tool":    "{\"tools\":[{\"name\":\"a\",\"description\":\"\xff\"}]}",
		"invalid UTF-8 in a key":     "{\"tools\":[{\"name\":\"a\",\"x\xff\":1}]}",
		"encoded surrogate in a key": "{\"tools\":[{\"name\":\"a\",\"x\xed\xa0\x80\":1}]}",
		"tools is an object":         `{"tools":{}}`,
		"tools is null":              `{"tools":null}`,
		"tools missing":              `{}`,
		"nextCursor is a number":     `{"tools":[],"nextCursor":5}`,
		"nextCursor too long":        `{"tools":[],"nextCursor":"` + longCursor + `"}`,
		"result is an array":         `[]`,
		"result has trailing data":   `{"tools":[]} {}`,
		"truncated result":           `{"tools":[{"name":"a"`,
		"non-string key in object":   `{1:2}`,
		"bare scalar as result":      `42`,
		"tools array holds garbage":  `{"tools":[{"name":"a"} x]}`,
		"nextCursor is a nested obj": `{"tools":[],"nextCursor":{}}`,
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, modeJSON, func(int, string) string { return result })
			res, err := ListTools(context.Background(), f.url(), testOptions())
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
			if len(res.Tools) != 0 || len(res.Unusable) != 0 {
				t.Errorf("a failed crawl returned a result: %+v", res)
			}
		})
	}
}

func TestMalformedInitializeResults(t *testing.T) {
	cases := map[string]string{
		"no protocol version":               `{}`,
		"protocol version number":           `{"protocolVersion":5}`,
		"protocol version has space":        `{"protocolVersion":"2025 06"}`,
		"protocol version header injection": `{"protocolVersion":"2025-06-18\r\nX: y"}`,
		"protocol version too long":         `{"protocolVersion":"` + strings.Repeat("1", maxProtocolVersionBytes+1) + `"}`,
		"result is a string":                `"hello"`,
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
			f.initResult = result
			_, err := ListTools(context.Background(), f.url(), testOptions())
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestBadServerInfoIsIgnored(t *testing.T) {
	f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
	f.initResult = `{"protocolVersion":"2025-03-26","serverInfo":"not an object"}`
	res, err := ListTools(context.Background(), f.url(), testOptions())
	if err != nil || res.ServerName != "" || res.ProtocolVersion != "2025-03-26" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestUnusableSessionID(t *testing.T) {
	for _, id := range []string{"has space", strings.Repeat("s", maxSessionIDBytes+1)} {
		f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
		f.override = func(w http.ResponseWriter, _ *http.Request, in rpcIn) bool {
			if in.Method != methodInitialize {
				return false
			}
			w.Header().Set(headerSessionID, id)
			f.reply(w, in.ID, defaultInitResult)
			return true
		}
		if _, err := ListTools(context.Background(), f.url(), testOptions()); !errors.Is(err, ErrMalformed) {
			t.Errorf("session id %.12q: err = %v, want ErrMalformed", id, err)
		}
	}
}

func TestBadResponseFraming(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, in rpcIn){
		"text/plain content type": func(w http.ResponseWriter, in rpcIn) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, in.ID)
		},
		"no content type": func(w http.ResponseWriter, in rpcIn) {
			w.Header()["Content-Type"] = nil
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, in.ID)
		},
		"json answers another id": func(w http.ResponseWriter, _ rpcIn) {
			w.Header().Set("Content-Type", mediaJSON)
			_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":9999,"result":{"tools":[]}}`)
		},
		"json is a batch": func(w http.ResponseWriter, in rpcIn) {
			w.Header().Set("Content-Type", mediaJSON)
			_, _ = fmt.Fprintf(w, `[{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}]`, in.ID)
		},
		"json has neither result nor error": func(w http.ResponseWriter, in rpcIn) {
			w.Header().Set("Content-Type", mediaJSON)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s}`, in.ID)
		},
		"json result is null": func(w http.ResponseWriter, in rpcIn) {
			w.Header().Set("Content-Type", mediaJSON)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":null}`, in.ID)
		},
		"json error is not an object": func(w http.ResponseWriter, in rpcIn) {
			w.Header().Set("Content-Type", mediaJSON)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":"boom"}`, in.ID)
		},
		"json empty body": func(w http.ResponseWriter, _ rpcIn) {
			w.Header().Set("Content-Type", mediaJSON)
		},
		"sse without a response": func(w http.ResponseWriter, _ rpcIn) {
			w.Header().Set("Content-Type", mediaSSE)
			_, _ = fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}\n\n")
		},
		"sse event that is not json": func(w http.ResponseWriter, _ rpcIn) {
			w.Header().Set("Content-Type", mediaSSE)
			_, _ = fmt.Fprint(w, "data: hello\n\n")
		},
		"sse empty stream": func(w http.ResponseWriter, _ rpcIn) {
			w.Header().Set("Content-Type", mediaSSE)
		},
		"accepted with no body": func(w http.ResponseWriter, _ rpcIn) {
			w.WriteHeader(http.StatusAccepted)
		},
	}
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
			f.override = func(w http.ResponseWriter, _ *http.Request, in rpcIn) bool {
				if in.Method != methodToolsList {
					return false
				}
				respond(w, in)
				return true
			}
			_, err := ListTools(context.Background(), f.url(), testOptions())
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestInvalidOptions(t *testing.T) {
	ok := testOptions()
	neg := func(mut func(*Options)) Options {
		o := ok
		mut(&o)
		return o
	}
	cases := map[string]struct {
		endpoint string
		opt      Options
	}{
		"no client":            {"http://127.0.0.1:1/", Options{}},
		"empty endpoint":       {"", ok},
		"ftp endpoint":         {"ftp://example.com/", ok},
		"no host":              {"http:///path", ok},
		"relative endpoint":    {"/mcp", ok},
		"unparsable":           {"http://[::1", ok},
		"negative pages":       {"http://127.0.0.1:1/", neg(func(o *Options) { o.MaxPages = -1 })},
		"negative tools":       {"http://127.0.0.1:1/", neg(func(o *Options) { o.MaxTools = -1 })},
		"negative message":     {"http://127.0.0.1:1/", neg(func(o *Options) { o.MaxMessageBytes = -1 })},
		"negative tool bytes":  {"http://127.0.0.1:1/", neg(func(o *Options) { o.MaxToolBytes = -1 })},
		"negative total bytes": {"http://127.0.0.1:1/", neg(func(o *Options) { o.MaxTotalBytes = -1 })},
		"negative timeout":     {"http://127.0.0.1:1/", neg(func(o *Options) { o.Timeout = -time.Second })},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ListTools(context.Background(), tc.endpoint, tc.opt); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("err = %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func TestConnectionRefused(t *testing.T) {
	f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
	url := f.url()
	f.srv.Close()
	if _, err := ListTools(context.Background(), url, testOptions()); err == nil {
		t.Fatal("want a connection error")
	}
}
