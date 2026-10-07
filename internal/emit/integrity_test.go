package emit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func freshOutput(t *testing.T) Output {
	t.Helper()
	out, err := AgentGateway(goldenCases()[0].input)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// splitHeader returns the header (through the hash line, newline included)
// and the body that follows it.
func splitHeader(t *testing.T, file []byte) (string, []byte) {
	t.Helper()
	parts := bytes.SplitN(file, []byte("\n"), headerLines+1)
	if len(parts) != headerLines+1 {
		t.Fatalf("file has fewer than %d lines:\n%s", headerLines+1, file)
	}
	header := string(bytes.Join(parts[:headerLines], []byte("\n"))) + "\n"
	return header, parts[headerLines]
}

func TestVerifyFreshOutput(t *testing.T) {
	out := freshOutput(t)
	got, ok := Verify(out.YAML)
	if !ok || got != out.BodyHash {
		t.Fatalf("Verify(fresh) = %q, %v; BodyHash %q", got, ok, out.BodyHash)
	}
	if !hexDigest.MatchString(out.BodyHash) {
		t.Errorf("BodyHash %q is not 64 lowercase hex digits", out.BodyHash)
	}
	header, body := splitHeader(t, out.YAML)
	sum := sha256.Sum256(body)
	if want := hex.EncodeToString(sum[:]); want != out.BodyHash {
		t.Errorf("BodyHash %q is not the SHA-256 of the body %q", out.BodyHash, want)
	}
	if !strings.HasPrefix(header, generatedHeader) || !strings.HasSuffix(header, hashLinePrefix+out.BodyHash+"\n") {
		t.Errorf("unexpected header:\n%s", header)
	}
}

// TestVerifyDetectsProcessorRemoval ports the review scenario: the
// mcpGuardrails block is deleted from the file on disk. The gateway would
// reload that with one log line and serve every new session without the
// processor; Verify is what lets the owner of the file notice.
func TestVerifyDetectsProcessorRemoval(t *testing.T) {
	out := freshOutput(t)
	start := bytes.Index(out.YAML, []byte("    mcpGuardrails:\n"))
	end := bytes.Index(out.YAML, []byte("  backends:\n"))
	if start < 0 || end < start {
		t.Fatal("setup: blocks not found")
	}
	edited := slices.Concat(out.YAML[:start], out.YAML[end:])
	got, ok := Verify(edited)
	if ok {
		t.Fatalf("file without its processor verified")
	}
	if got == "" || got == out.BodyHash {
		t.Errorf("bodyHash should be the digest of the edited body, got %q", got)
	}
}

// TestVerifyDetectsAnyBodyEdit includes the F2 edit: widening bindAddress to
// a wildcard on disk must fail Verify like every other change.
func TestVerifyDetectsAnyBodyEdit(t *testing.T) {
	out := freshOutput(t)
	edits := map[string]func([]byte) []byte{
		"fail open": func(f []byte) []byte { return bytes.Replace(f, []byte(`"failClosed"`), []byte(`"failOpen"`), 1) },
		"allow widened": func(f []byte) []byte {
			return bytes.Replace(f, []byte(`- allow: "mcp.tool.name`), []byte(`- allow: "true || mcp.tool.name`), 1)
		},
		"admin unpinned": func(f []byte) []byte {
			return bytes.Replace(f, []byte(`adminAddr: "127.0.0.1:15000"`), []byte(`adminAddr: "0.0.0.0:15000"`), 1)
		},
		"bind unpinned": func(f []byte) []byte {
			return bytes.Replace(f, []byte(`bindAddress: "127.0.0.1"`), []byte(`bindAddress: "0.0.0.0"`), 1)
		},
		"route detached": func(f []byte) []byte {
			return bytes.Replace(f, []byte("  gateways: \"toolwarrant\"\n"), nil, 1)
		},
		"trailing newline": func(f []byte) []byte { return append(f, '\n') },
		"truncated":        func(f []byte) []byte { return f[:len(f)-1] },
	}
	for name, edit := range edits {
		edited := edit(slices.Clone(out.YAML))
		if bytes.Equal(edited, out.YAML) {
			t.Fatalf("%s: setup: edit did not apply", name)
		}
		if _, ok := Verify(edited); ok {
			t.Errorf("%s: edited file verified", name)
		}
	}
}

func TestVerifyRejectsMissingOrMalformedHeader(t *testing.T) {
	out := freshOutput(t)
	_, body := splitHeader(t, out.YAML)
	hashLine := hashLinePrefix + out.BodyHash + "\n"
	unrecognisable := map[string][]byte{
		"empty":                 {},
		"body only":             body,
		"header without hash":   []byte(generatedHeader + string(body)),
		"hash line only":        []byte(hashLine + string(body)),
		"hash line moved first": []byte(hashLine + generatedHeader + string(body)),
		"no newline after hex":  []byte(generatedHeader + hashLinePrefix + out.BodyHash),
		"edited header comment": bytes.Replace(out.YAML, []byte("Do not edit"), []byte("Do edit"), 1),
	}
	for name, file := range unrecognisable {
		if got, ok := Verify(file); ok || got != "" {
			t.Errorf("%s: Verify = %q, %v; want \"\", false", name, got, ok)
		}
	}
	wrongDigest := map[string][]byte{
		"uppercase hex": []byte(generatedHeader + hashLinePrefix + strings.ToUpper(out.BodyHash) + "\n" + string(body)),
		"zero digest":   []byte(generatedHeader + hashLinePrefix + strings.Repeat("0", hashHexLen) + "\n" + string(body)),
	}
	for name, file := range wrongDigest {
		if got, ok := Verify(file); ok || got != out.BodyHash {
			t.Errorf("%s: Verify = %q, %v; want the real body digest and false", name, got, ok)
		}
	}
}

// TestVerifyGoldenFiles makes a hand edit of a golden file fail the suite the
// same way an edited deployed config fails the canary.
func TestVerifyGoldenFiles(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil || len(files) < len(goldenCases()) {
		t.Fatalf("want at least %d golden files, got %v (%v)", len(goldenCases()), files, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := Verify(data); !ok {
			t.Errorf("%s does not verify: edited by hand or written by an older emitter", file)
		}
	}
}

func TestSealRoundTrip(t *testing.T) {
	for _, body := range [][]byte{{}, []byte("x"), []byte("config:\n"), bytes.Repeat([]byte("a\n"), 10000)} {
		file, digest := seal(body)
		got, ok := Verify(file)
		if !ok || got != digest {
			t.Errorf("seal/Verify mismatch for %d-byte body: %q %v vs %q", len(body), got, ok, digest)
		}
		if !bytes.HasSuffix(file, body) || !bytes.HasPrefix(file, []byte(generatedHeader)) {
			t.Errorf("sealed file does not wrap the body")
		}
	}
}

// FuzzSealVerify: whatever the body, a sealed file verifies and any single
// flipped bit anywhere in it does not.
func FuzzSealVerify(f *testing.F) {
	f.Add([]byte("config:\nbinds:\n"), 7)
	f.Add([]byte{}, 0)
	f.Fuzz(func(t *testing.T, body []byte, pos int) {
		file, digest := seal(body)
		if got, ok := Verify(file); !ok || got != digest {
			t.Fatalf("sealed file does not verify")
		}
		if pos < 0 {
			pos = -pos
		}
		mutated := slices.Clone(file)
		mutated[pos%len(mutated)] ^= 0x01
		if _, ok := Verify(mutated); ok {
			t.Fatalf("mutated byte %d still verifies", pos%len(mutated))
		}
	})
}
