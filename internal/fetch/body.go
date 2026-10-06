package fetch

import (
	"fmt"
	"io"
	"math"
	"sync"
)

// cappedBody wraps a response body and fails with ErrTooLarge as soon as more
// than limit bytes have been read from it.
//
// It sits above the transport's transparent gzip decoding, so it counts
// decompressed bytes: a small compressed body that inflates to gigabytes stops
// at the cap, and the underlying connection is closed at that moment instead
// of being drained.
type cappedBody struct {
	rc    io.ReadCloser
	limit int64

	// read, err are touched only by Read, which the io.Reader contract does
	// not allow to run concurrently.
	read int64
	err  error

	closeOnce sync.Once
	closeErr  error
}

func newCappedBody(rc io.ReadCloser, limit int64) *cappedBody {
	return &cappedBody{rc: rc, limit: limit}
}

// Read returns at most the bytes that fit under the cap. The read that would
// cross it returns the bytes still within the cap together with ErrTooLarge,
// and every later read returns ErrTooLarge.
func (b *cappedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Allow one byte past the limit so that overflow is detected without ever
	// handing the caller more than limit bytes.
	room := b.limit - b.read
	if room < math.MaxInt64 {
		room++
	}
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := b.rc.Read(p)
	b.read += int64(n)
	if b.read > b.limit {
		b.err = fmt.Errorf("%w: body exceeds %d bytes", ErrTooLarge, b.limit)
		_ = b.Close()
		return n - 1, b.err
	}
	return n, err
}

// Close closes the underlying body exactly once; later calls return the
// first result.
func (b *cappedBody) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.rc.Close() })
	return b.closeErr
}
