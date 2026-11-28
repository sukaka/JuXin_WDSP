package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeHealthcheckPrivOps struct {
	euid             int
	capPrm           uint64
	readCapPrmErr    error
	setNoNewPrivsErr error
	clearGroupsErr   error
	dropBSetErr      error
	setresgidErr     error
	setresuidErr     error
	clearCapsErr     error
	calls            []string
}

func (f *fakeHealthcheckPrivOps) Geteuid() int { return f.euid }
func (f *fakeHealthcheckPrivOps) ReadCapPrm() (uint64, error) {
	f.calls = append(f.calls, "read_cap_prm")
	return f.capPrm, f.readCapPrmErr
}
func (f *fakeHealthcheckPrivOps) SetNoNewPrivs() error {
	f.calls = append(f.calls, "no_new_privs")
	return f.setNoNewPrivsErr
}
func (f *fakeHealthcheckPrivOps) ClearGroups() error {
	f.calls = append(f.calls, "clear_groups")
	return f.clearGroupsErr
}
func (f *fakeHealthcheckPrivOps) DropAllBoundingCaps() error {
	f.calls = append(f.calls, "drop_bset")
	return f.dropBSetErr
}
func (f *fakeHealthcheckPrivOps) Setresgid(gid int) error {
	if gid != mirrorTargetGID {
		return errors.New("unexpected gid")
	}
	f.calls = append(f.calls, "setresgid:1000")
	return f.setresgidErr
}
func (f *fakeHealthcheckPrivOps) Setresuid(uid int) error {
	if uid != mirrorTargetUID {
		return errors.New("unexpected uid")
	}
	f.calls = append(f.calls, "setresuid:1000")
	return f.setresuidErr
}
func (f *fakeHealthcheckPrivOps) ClearCapabilities() error {
	f.calls = append(f.calls, "clear_caps")
	return f.clearCapsErr
}

func TestHasHealthcheckFlag(t *testing.T) {
	if !hasHealthcheckFlag([]string{"--healthcheck"}) {
		t.Fatal("expected true for --healthcheck")
	}
	if !hasHealthcheckFlag([]string{"--foo", "--healthcheck"}) {
		t.Fatal("expected true when --healthcheck is present")
	}
	if hasHealthcheckFlag([]string{"--other"}) || hasHealthcheckFlag(nil) {
		t.Fatal("expected false when --healthcheck is absent")
	}
}

func TestDropHealthcheckPrivilegesWith_RootAndDropEnabled(t *testing.T) {
	t.Setenv("MIRROR_DROP_PRIVS", "1")
	ops := &fakeHealthcheckPrivOps{
		euid:   0,
		capPrm: 1 << uint(capSetPCap), // 即使无 CAP_NET_RAW 也应正常降权
	}
	if err := dropHealthcheckPrivilegesWith(ops); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"no_new_privs",
		"clear_groups",
		"read_cap_prm",
		"drop_bset",
		"setresgid:1000",
		"setresuid:1000",
		"clear_caps",
	}
	if !reflect.DeepEqual(ops.calls, want) {
		t.Fatalf("calls = %v, want %v", ops.calls, want)
	}
}

func TestDropHealthcheckPrivilegesWith_NoSetPCapSkipsBoundingDrop(t *testing.T) {
	t.Setenv("MIRROR_DROP_PRIVS", "true")
	ops := &fakeHealthcheckPrivOps{
		euid:   0,
		capPrm: 0,
	}
	if err := dropHealthcheckPrivilegesWith(ops); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"no_new_privs",
		"clear_groups",
		"read_cap_prm",
		"setresgid:1000",
		"setresuid:1000",
		"clear_caps",
	}
	if !reflect.DeepEqual(ops.calls, want) {
		t.Fatalf("calls = %v, want %v", ops.calls, want)
	}
}

func TestDropHealthcheckPrivilegesWith_SkipsWhenDisabledOrNonRoot(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		t.Setenv("MIRROR_DROP_PRIVS", "0")
		ops := &fakeHealthcheckPrivOps{euid: 0, capPrm: 1 << uint(capSetPCap)}
		if err := dropHealthcheckPrivilegesWith(ops); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ops.calls) != 0 {
			t.Fatalf("expected no syscalls when disabled, got %v", ops.calls)
		}
	})
	t.Run("non-root", func(t *testing.T) {
		t.Setenv("MIRROR_DROP_PRIVS", "1")
		ops := &fakeHealthcheckPrivOps{euid: 1000, capPrm: 0}
		if err := dropHealthcheckPrivilegesWith(ops); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ops.calls) != 0 {
			t.Fatalf("expected no syscalls for non-root, got %v", ops.calls)
		}
	})
}

func TestDropHealthcheckPrivilegesWith_FailsClosedOnError(t *testing.T) {
	t.Setenv("MIRROR_DROP_PRIVS", "1")
	boom := errors.New("eperm")
	cases := []struct {
		name string
		ops  *fakeHealthcheckPrivOps
		want string
	}{
		{"no_new_privs", &fakeHealthcheckPrivOps{euid: 0, setNoNewPrivsErr: boom}, "PR_SET_NO_NEW_PRIVS"},
		{"clear_groups", &fakeHealthcheckPrivOps{euid: 0, clearGroupsErr: boom}, "Setgroups"},
		{"read_cap_prm", &fakeHealthcheckPrivOps{euid: 0, readCapPrmErr: boom}, "CapPrm"},
		{"drop_bset", &fakeHealthcheckPrivOps{euid: 0, capPrm: 1 << uint(capSetPCap), dropBSetErr: boom}, "bounding caps"},
		{"setresgid", &fakeHealthcheckPrivOps{euid: 0, setresgidErr: boom}, "Setresgid"},
		{"setresuid", &fakeHealthcheckPrivOps{euid: 0, setresuidErr: boom}, "Setresuid"},
		{"clear_caps", &fakeHealthcheckPrivOps{euid: 0, clearCapsErr: boom}, "clear caps"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := dropHealthcheckPrivilegesWith(tc.ops)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRunHealthcheck_SymlinkedRulesDir(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		t.Fatal(err)
	}
	rulesRoot := filepath.Join(root, "rules")
	relDir := filepath.Join(rulesRoot, "releases", "builtin-1.20.1")
	if err := os.MkdirAll(relDir, 0o750); err != nil {
		t.Fatal(err)
	}
	currentLink := filepath.Join(rulesRoot, "current")
	if err := os.Symlink(filepath.Join("releases", "builtin-1.20.1"), currentLink); err != nil {
		t.Fatal(err)
	}

	t.Setenv("MIRROR_EVENTS_LOG", filepath.Join(logDir, "api-runtime-events.log"))
	t.Setenv("MIRROR_RULES_DIR", currentLink)

	if err := runHealthcheck(); err != nil {
		t.Fatalf("runHealthcheck failed on valid symlinked rules dir: %v", err)
	}

	// 断链必须失败
	brokenLink := filepath.Join(rulesRoot, "broken")
	if err := os.Symlink(filepath.Join("releases", "missing"), brokenLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MIRROR_RULES_DIR", brokenLink)
	if err := runHealthcheck(); err == nil {
		t.Fatal("expected runHealthcheck to fail on broken symlink")
	}
}
