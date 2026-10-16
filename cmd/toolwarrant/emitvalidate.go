package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// envGatewayBinary names the agentgateway binary emit validates with when
	// --gateway-binary is not given.
	envGatewayBinary = "TOOLWARRANT_AGENTGATEWAY"
	// validateOnlyFlag is the gateway's own check: it parses and validates
	// the file and exits without serving.
	validateOnlyFlag = "--validate-only"
	// validateTimeout bounds the gateway's check; it takes well under a second.
	validateTimeout = 60 * time.Second
	// maxGatewayOutput caps how much of the gateway's message is printed.
	maxGatewayOutput = 4096
	// tempPattern names the staged file next to the target. It ends in .yaml
	// so the gateway binary reads it as the YAML it is.
	tempPattern = ".toolwarrant-*.tmp.yaml"
	truncated   = "..."
)

// gatewayRefusal is a staged file the gateway binary did not accept. The
// message is the gateway's own, bounded and on one line; describe escapes it
// when it is printed.
type gatewayRefusal struct {
	binary string
	output string
}

func (e *gatewayRefusal) Error() string {
	return fmt.Sprintf("the gateway binary %s refused the configuration, so nothing was written: %s", e.binary, e.output)
}

// writeValidated replaces path with data through a temporary file in the same
// directory and a rename, so the gateway never reads a half-written file. The
// mode is set on the temporary file before the rename, so a file that carries
// a secret is never readable by others for even an instant. When binary is
// set, the gateway binary must accept the staged file (<binary> -f FILE
// --validate-only) before it is renamed into place: a file the gateway would
// refuse must fail emit instead of freezing every server's configuration on
// the next reload (the gateway keeps its previous state), and must leave no
// file behind.
func writeValidated(ctx context.Context, path string, data []byte, mode os.FileMode, binary string) (err error) {
	tmp, err := stageFile(path, data, mode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp) // the original error is the one to report
		}
	}()
	if binary != "" {
		if err = validateWithGateway(ctx, binary, tmp); err != nil {
			return err
		}
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// stageFile writes data to a new temporary file next to path with the given
// mode and returns its name. On any failure the temporary file is removed.
func stageFile(path string, data []byte, mode os.FileMode) (name string, err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), tempPattern)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err = tmp.Chmod(mode); err != nil {
		return "", fmt.Errorf("set file mode: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return "", fmt.Errorf("sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return tmp.Name(), nil
}

// validateWithGateway runs the gateway binary on the staged file. A binary
// that cannot be run is an error of its own; a binary that exits non-zero
// refused the file and its message is returned.
func validateWithGateway(ctx context.Context, binary, file string) error {
	vctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()
	out, err := exec.CommandContext(vctx, binary, "-f", file, validateOnlyFlag).CombinedOutput()
	if err == nil {
		return nil
	}
	if vctx.Err() != nil {
		return fmt.Errorf("the gateway binary %s did not finish %s within %s", binary, validateOnlyFlag, validateTimeout)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return fmt.Errorf("run gateway binary %s: %w", binary, err)
	}
	return &gatewayRefusal{binary: binary, output: oneLine(out)}
}

// oneLine folds the gateway's output onto one bounded line.
func oneLine(out []byte) string {
	s := strings.Join(strings.Fields(string(out)), " ")
	if s == "" {
		return "(no message)"
	}
	if len(s) > maxGatewayOutput {
		s = s[:maxGatewayOutput] + truncated
	}
	return s
}
