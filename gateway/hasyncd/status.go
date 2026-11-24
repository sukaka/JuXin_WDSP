package hasyncd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxStatusFileBytes  int64 = 1 << 20 // 1 MiB
	maxIfacesTailBytes  int64 = 2 << 20 // 2 MiB
	maxInterfacesResult       = 256
)

func readStatusJSONWithMtime(path string) (json.RawMessage, *time.Time) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Printf("[hasyncd] WARN: stat status file %q: %v", path, err)
		}
		return nil, nil
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		log.Printf("[hasyncd] WARN: status file %q is symlink or non-regular", path)
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[hasyncd] WARN: open status file %q: %v", path, err)
		return nil, nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxStatusFileBytes+1))
	if err != nil {
		log.Printf("[hasyncd] WARN: read status file %q: %v", path, err)
		return nil, nil
	}
	if int64(len(raw)) > maxStatusFileBytes {
		log.Printf("[hasyncd] WARN: status file %q exceeds %d bytes", path, maxStatusFileBytes)
		return nil, nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || !json.Valid(raw) {
		log.Printf("[hasyncd] WARN: status file %q contains invalid JSON", path)
		return nil, nil
	}
	mtime := fi.ModTime().UTC()
	return json.RawMessage(raw), &mtime
}

// readInterfacesTail parses the tail of node-interfaces.jsonl and returns the latest
// snapshot per interface name sorted deterministically by ifname. Always returns a non-nil slice.
func readInterfacesTail(path string) []InterfaceSnapshot {
	out := make([]InterfaceSnapshot, 0)
	if strings.TrimSpace(path) == "" {
		return out
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Printf("[hasyncd] WARN: stat interfaces log %q: %v", path, err)
		}
		return out
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[hasyncd] WARN: open interfaces log %q: %v", path, err)
		return out
	}
	defer f.Close()

	var offset int64
	if fi.Size() > maxIfacesTailBytes {
		offset = fi.Size() - maxIfacesTailBytes
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return out
		}
	}

	reader := bufio.NewReader(f)
	if offset > 0 {
		// Discard potentially truncated first line after seeking into the middle of the file.
		_, _ = reader.ReadBytes('\n')
	}

	latest := make(map[string]InterfaceSnapshot)
	for {
		line, err := reader.ReadBytes('\n')
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			var snap InterfaceSnapshot
			if uerr := json.Unmarshal(trimmed, &snap); uerr == nil && snap.IfName != "" {
				if snap.IPAddresses == nil {
					snap.IPAddresses = []string{}
				}
				if _, exists := latest[snap.IfName]; exists || len(latest) < maxInterfacesResult {
					latest[snap.IfName] = snap
				}
			}
		}
		if err != nil {
			break
		}
	}

	names := make([]string, 0, len(latest))
	for name := range latest {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, latest[name])
	}
	return out
}

func resolveVersion(explicit, versionFile string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	candidates := make([]string, 0, 2)
	if vf := strings.TrimSpace(versionFile); vf != "" {
		candidates = append(candidates, vf)
	} else {
		candidates = append(candidates, "/app/VERSION")
	}
	for _, p := range candidates {
		b, err := os.ReadFile(filepath.Clean(p))
		if err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	return "unknown"
}
