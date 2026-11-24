package hasyncd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// WriteHealthStamp atomically writes the daemon health stamp file (0600).
func WriteHealthStamp(path string, stamp HealthStamp) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("health stamp path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create health stamp dir: %w", err)
	}
	if err := checkNotSymlinkIfExists(path); err != nil {
		return err
	}
	raw, err := json.Marshal(stamp)
	if err != nil {
		return fmt.Errorf("marshal health stamp: %w", err)
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(dir, ".hasyncd-health-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp health stamp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod health stamp: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write health stamp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close health stamp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename health stamp: %w", err)
	}
	return nil
}

// CheckHealthStamp validates the local health stamp file for `hasyncd --healthcheck`.
// Zero unauthenticated TCP endpoints are exposed; readiness is verified locally via the stamp file.
func CheckHealthStamp(path string, now time.Time, maxAge time.Duration) error {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultHealthStampPath
	}
	if maxAge <= 0 {
		maxAge = DefaultHealthStampMaxAge
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("health stamp unreadable: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return errors.New("health stamp is not a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read health stamp: %w", err)
	}
	var stamp HealthStamp
	if err := json.Unmarshal(raw, &stamp); err != nil {
		return fmt.Errorf("parse health stamp: %w", err)
	}
	if !stamp.Ready {
		return errors.New("hasyncd reports not ready")
	}
	if stamp.UpdatedAt.IsZero() {
		return errors.New("health stamp missing updated_at")
	}
	age := now.UTC().Sub(stamp.UpdatedAt.UTC())
	if age > maxAge {
		return fmt.Errorf("health stamp stale (age %s > %s)", age.Round(time.Second), maxAge)
	}
	if age < -10*time.Second {
		return fmt.Errorf("health stamp timestamp is in the future (%s)", age.Round(time.Second))
	}
	if stamp.PID > 0 {
		if err := syscall.Kill(stamp.PID, 0); err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("hasyncd process pid=%d not alive: %w", stamp.PID, err)
		}
	}
	return nil
}
