package fetch

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- cappedBody unit tests -------------------------------------------------

type countingCloser struct {
	io.Reader
	closes int
}

func (c *countingCloser) Close() error { c.closes++; return nil }

func TestCappedBodyLimits(t *testing.T) {
	const limit = 100
	cases := []struct {
		name     string
		size     int
		wantRead int
		wantErr  error
	}{
		{"empty", 0, 0, nil},
		{"under", limit - 1, limit - 1, nil},
		{"exactly at the limit", limit, limit, nil},
		{"one over", limit + 1, limit, ErrTooLarge},
		{"far over", 10 * limit, limit, ErrTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := &countingCloser{Reader: bytes.NewReader(bytes.Repeat([]byte("a"), tc.size))}
			body := newCappedBody(rc, limit)
			data, err := io.ReadAll(body)
			if len(data) != tc.wantRead {
				t.Errorf("read %d bytes, want %d", len(data), tc.wantRead)
			}
			if tc.wantErr == nil && err != nil {
				t.Errorf("unexpected error %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("got %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil && rc.closes != 1 {
				t.Errorf("underlying body closed %d times on overflow, want 1", rc.closes)
			}
		})
	}
}

func TestCappedBodyOverflowIsSticky(t *testing.T) {
	rc := &countingCloser{Reader: strings.NewReader(strings.Repeat("a", 50))}
	body := newCappedBody(rc, 10)
	buf := make([]byte, 64)
	n, err := body.Read(buf)
	if n != 10 || !errors.Is(err, ErrTooLarge) {
		t.Fatalf("first read = (%d, %v), want (10, ErrTooLarge)", n, err)
	}
	for i := 0; i < 3; i++ {
		if n, err := body.Read(buf); n != 0 || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("later read = (%d, %v), want (0, ErrTooLarge)", n, err)
		}
	}
	_ = body.Close()
	_ = body.Close()
	if rc.closes != 1 {
		t.Fatalf("underlying Close called %d times, want 1", rc.closes)
	}
}

func TestCappedBodyEdgeCases(t *testing.T) {
	t.Run("zero-length read", func(t *testing.T) {
		body := newCappedBody(io.NopCloser(strings.NewReader("abc")), 10)
		if n, err := body.Read(nil); n != 0 || err != nil {
			t.Fatalf("Read(nil) = (%d, %v)", n, err)
		}
	})
	t.Run("huge limit does not overflow", func(t *testing.T) {
		body := newCappedBody(io.NopCloser(strings.NewReader("abc")), math.MaxInt64)
		data, err := io.ReadAll(body)
		if err != nil || string(data) != "abc" {
			t.Fatalf("got (%q, %v)", data, err)
		}
	})
	t.Run("source error passes through", func(t *testing.T) {
		boom := errors.New("boom")
		body := newCappedBody(io.NopCloser(io.MultiReader(strings.NewReader("ab"), errReader{boom})), 100)
		data, err := io.ReadAll(body)
		if string(data) != "ab" || !errors.Is(err, boom) {
			t.Fatalf("got (%q, %v)", data, err)
		}
	})
	t.Run("small reads cannot slip past the cap", func(t *testing.T) {
		body := newCappedBody(io.NopCloser(strings.NewReader(strings.Repeat("a", 20))), 10)
		total := 0
		var err error
		buf := make([]byte, 3)
		for err == nil {
			var n int
			n, err = body.Read(buf)
			total += n
		}
		if total != 10 || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("total %d, err %v", total, err)
		}
	})
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// --- end-to-end size limits ------------------------------------------------

func sizedHandler(size int, declareLength bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if declareLength {
			w.Header().Set("Content-Length", strconv.Itoa(size))
		}
		chunk := bytes.Repeat([]byte("a"), 4096)
		for written := 0; written < size; {
			n := min(len(chunk), size-written)
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			if flusher, ok := w.(http.Flusher); ok && !declareLength {
				flusher.Flush() // forces chunked encoding even for a small body
			}
			written += n
		}
	}
}

func TestBodyLimitEndToEnd(t *testing.T) {
	const limit = 1000
	cases := []struct {
		name          string
		size          int
		declareLength bool
		wantDoErr     bool // refused before any body is read
		wantReadErr   bool
		wantBytes     int
	}{
		{"within limit with content-length", limit, true, false, false, limit},
		{"within limit chunked", limit, false, false, false, limit},
		{"over with content-length", 5 * limit, true, true, false, 0},
		{"over chunked", 5 * limit, false, false, true, limit},
		{"one byte over chunked", limit + 1, false, false, true, limit},
		{"one byte over with content-length", limit + 1, true, true, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, sizedHandler(tc.size, tc.declareLength))
			client := newTestClient(t, Policy{AllowPrivate: true, MaxResponseBytes: limit})
			resp, err := get(client, srv.URL)
			if tc.wantDoErr {
				if !errors.Is(err, ErrTooLarge) || resp != nil {
					t.Fatalf("Do = (%v, %v), want ErrTooLarge and no response", resp, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if len(data) != tc.wantBytes {
				t.Errorf("read %d bytes, want %d", len(data), tc.wantBytes)
			}
			if tc.wantReadErr != errors.Is(err, ErrTooLarge) {
				t.Errorf("read error = %v, want ErrTooLarge=%v", err, tc.wantReadErr)
			}
		})
	}
}

func gzipBombHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			http.Error(w, "this test server only speaks gzip", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		zeros := make([]byte, 64<<10)
		for i := 0; i < 1024; i++ { // 64 MiB once inflated, a few tens of KiB on the wire
			if _, err := gz.Write(zeros); err != nil {
				return
			}
			if i%16 == 0 {
				_ = gz.Flush()
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
		_ = gz.Close()
	}
}

func TestGzipBombStopsAtTheCap(t *testing.T) {
	const limit = 1 << 20
	srv := startServer(t, gzipBombHandler(t))
	client := newTestClient(t, Policy{AllowPrivate: true, MaxResponseBytes: limit})

	for _, explicitEncoding := range []string{"", "gzip", "gzip, deflate, br"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if explicitEncoding != "" {
			req.Header.Set("Accept-Encoding", explicitEncoding)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Accept-Encoding %q: Do: %v", explicitEncoding, err)
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("Accept-Encoding %q: read error %v, want ErrTooLarge", explicitEncoding, err)
		}
		if len(data) != limit {
			t.Errorf("Accept-Encoding %q: read %d bytes, want exactly the cap of %d", explicitEncoding, len(data), limit)
		}
	}
}

func TestResponseHeaderOverflow(t *testing.T) {
	srv := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Padding", strings.Repeat("a", 70<<10))
		_, _ = w.Write([]byte("body"))
	}))
	client := newTestClient(t, Policy{AllowPrivate: true})
	_, err := get(client, srv.URL)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	// Pin the standard library's wording that mapTransportError relies on.
	if !strings.Contains(err.Error(), headerOverflowText) {
		t.Fatalf("net/http changed its header-overflow message: %v", err)
	}
}

func TestOtherTransportErrorsAreNotMappedToTooLarge(t *testing.T) {
	err := errors.New("connection reset")
	if got := mapTransportError(err); got != err || errors.Is(got, ErrTooLarge) {
		t.Fatalf("mapTransportError rewrote an unrelated error: %v", got)
	}
}

// --- timeouts --------------------------------------------------------------

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestSlowLorisBodyTimesOut(t *testing.T) {
	srv := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		flusher.Flush()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-deadline:
				return
			case <-time.After(40 * time.Millisecond):
			}
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	client := newTestClient(t, Policy{AllowPrivate: true, Timeout: 300 * time.Millisecond})

	start := time.Now()
	resp, err := get(client, srv.URL)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if !isTimeout(err) {
		t.Fatalf("read error = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the trickle ran for %v; the overall timeout did not apply", elapsed)
	}
}

func TestSlowLorisHeadersTimeOut(t *testing.T) {
	srv := startServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	client := newTestClient(t, Policy{AllowPrivate: true, Timeout: 300 * time.Millisecond})

	start := time.Now()
	_, err := get(client, srv.URL)
	if !isTimeout(err) {
		t.Fatalf("got %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("waited %v for headers; the timeout did not apply", elapsed)
	}
}

// flakyServer answers the first request normally and then hangs up on every
// later one without a response. On a reused keep-alive connection net/http
// silently replays an idempotent request in that situation.
func flakyServer(t *testing.T) (string, *hitCounter) {
	hits := &hitCounter{}
	srv := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.inc()
		if hits.count() == 1 {
			_, _ = w.Write([]byte("ok"))
			return
		}
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	return srv.URL, hits
}

func TestNoAutomaticRetry(t *testing.T) {
	t.Run("control: the default client retries this scenario", func(t *testing.T) {
		rawURL, hits := flakyServer(t)
		plain := &http.Client{Timeout: 5 * time.Second}
		if _, err := getBody(plain, rawURL); err != nil {
			t.Fatalf("first request: %v", err)
		}
		if _, err := get(plain, rawURL); err == nil {
			t.Fatal("expected the second request to fail")
		}
		if hits.count() != 3 {
			t.Skipf("net/http no longer retries here (server saw %d requests); the check below proves nothing", hits.count())
		}
	})
	t.Run("guarded client does not retry", func(t *testing.T) {
		rawURL, hits := flakyServer(t)
		client := newTestClient(t, Policy{AllowPrivate: true})
		if _, err := getBody(client, rawURL); err != nil {
			t.Fatalf("first request: %v", err)
		}
		if _, err := get(client, rawURL); err == nil {
			t.Fatal("expected the second request to fail")
		}
		if hits.count() != 2 {
			t.Fatalf("server saw %d requests for 2 calls; the client retried", hits.count())
		}
	})
}
