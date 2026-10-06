package fetch

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

// TestResponseHeaderOverflow pins the net/http wording mapTransportError relies
// on against the Go version the tests run with: when a release changes it, the
// condition would silently become a generic transport error, and this test
// fails instead.
func TestResponseHeaderOverflow(t *testing.T) {
	srv := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Padding", strings.Repeat("a", 70<<10))
		_, _ = w.Write([]byte("body"))
	}))
	client := newTestClient(t, Policy{AllowPrivate: true})
	_, err := get(client, srv.URL)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%s: got %v, want ErrTooLarge (if net/http changed its wording, update headerOverflowFormat)", runtime.Version(), err)
	}
	if !strings.HasSuffix(err.Error(), headerOverflowText()) {
		t.Fatalf("%s: error %q does not end in the pinned text %q", runtime.Version(), err, headerOverflowText())
	}
}

// rawServer answers every connection with exactly payload, so a test controls
// the status line and header bytes net/http parses.
func rawServer(t *testing.T, payload string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, payload)
			}(c)
		}
	}()
	return "http://" + ln.Addr().String() + "/"
}

// A server that writes the overflow wording into a status line or a header
// must not be able to relabel its own malformed response as ErrTooLarge
// (reviewer reproduction TestReview_HostileStatusLineTextCanTriggerTooLargeMapping,
// which did get errors.Is(err, ErrTooLarge) == true from the substring match).
func TestHostileHeaderTextCannotForgeTooLarge(t *testing.T) {
	phrase := headerOverflowText()
	cases := map[string]struct {
		payload string
		wantOK  bool // the response is well formed and delivered
	}{
		"header line without a colon": {"HTTP/1.1 200 OK\r\nX: y\r\nbad header line " + phrase + "\r\n\r\nok", false},
		"status line is the phrase":   {phrase + "\r\n\r\n", false},
		"header value is the phrase":  {"HTTP/1.1 200 OK\r\nX-Evil: " + phrase + "\r\nContent-Length: 2\r\n\r\nok", true},
		"reason phrase is the phrase": {"HTTP/1.1 200 " + phrase + "\r\nContent-Length: 2\r\n\r\nok", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, Policy{AllowPrivate: true})
			resp, err := get(client, rawServer(t, tc.payload))
			if err == nil {
				_ = resp.Body.Close()
			}
			if tc.wantOK != (err == nil) {
				t.Fatalf("err = %v, want error=%v", err, !tc.wantOK)
			}
			if errors.Is(err, ErrTooLarge) {
				t.Errorf("server-written text relabelled the error as ErrTooLarge: %v", err)
			}
		})
	}
}

func TestMapTransportErrorIsExact(t *testing.T) {
	exact := errors.New(headerOverflowText())
	cases := map[string]struct {
		err  error
		resp *http.Response
		want bool
	}{
		"exact text":                       {exact, nil, true},
		"exact text under net/http's wrap": {fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w", exact), nil, true},
		"text with a suffix":               {errors.New(headerOverflowText() + " x"), nil, false},
		"text after a hostile prefix":      {errors.New("malformed MIME header: missing colon: " + headerOverflowText()), nil, false},
		"another cap":                      {fmt.Errorf(headerOverflowFormat, 1), nil, false},
		"unrelated":                        {errors.New("connection reset"), nil, false},
		"exact text with a response":       {exact, &http.Response{Body: http.NoBody}, false},
	}
	for name, tc := range cases {
		got := mapTransportError(tc.resp, tc.err)
		if errors.Is(got, ErrTooLarge) != tc.want {
			t.Errorf("%s: ErrTooLarge=%v, want %v (%v)", name, !tc.want, tc.want, got)
		}
		if !tc.want && got != tc.err {
			t.Errorf("%s: an error that is not the overflow was rewritten: %v", name, got)
		}
	}
}

// bothRoundTripper breaks the RoundTripper contract by returning a response
// and an error together.
type bothRoundTripper struct{ body *countingCloser }

func (b *bothRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: b.body}, errors.New(headerOverflowText())
}

func TestRoundTripClosesAResponseReturnedWithAnError(t *testing.T) {
	body := &countingCloser{Reader: strings.NewReader("x")}
	g := &guardTransport{base: &bothRoundTripper{body: body}}
	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := g.RoundTrip(req)
	if resp != nil || err == nil || errors.Is(err, ErrTooLarge) {
		t.Fatalf("RoundTrip = (%v, %v), want no response and the unmapped error", resp, err)
	}
	if body.closes != 1 {
		t.Fatalf("stray response body closed %d times, want 1", body.closes)
	}
}
