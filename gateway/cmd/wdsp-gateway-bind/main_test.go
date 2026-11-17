package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var errInjected = errors.New("injected failure")

type fakeSystem struct {
	euid   int
	state  processState
	failAt string
	calls  []string
	uid    int
	gid    int
	path   string
	argv   []string
	env    []string
}

func newFakeSystem() *fakeSystem {
	return &fakeSystem{state: expectedState()}
}

func expectedState() processState {
	return processState{
		UIDs:       [4]int{targetUID, targetUID, targetUID, targetUID},
		GIDs:       [4]int{targetGID, targetGID, targetGID, targetGID},
		Groups:     []int{},
		CapInh:     expectedCapability,
		CapPrm:     expectedCapability,
		CapEff:     expectedCapability,
		CapBnd:     expectedCapability,
		CapAmb:     expectedCapability,
		NoNewPrivs: 1,
	}
}

func (f *fakeSystem) do(step string) error {
	f.calls = append(f.calls, step)
	if f.failAt == step {
		return errInjected
	}
	return nil
}

func (f *fakeSystem) EffectiveUID() int {
	f.calls = append(f.calls, "check-root")
	return f.euid
}

func (f *fakeSystem) SetNoNewPrivileges() error {
	return f.do("set-no-new-privileges")
}

func (f *fakeSystem) ClearSupplementaryGroups() error {
	return f.do("clear-supplementary-groups")
}

func (f *fakeSystem) PreserveCapabilitiesAcrossSetUID() error {
	return f.do("preserve-permitted-capabilities")
}

func (f *fakeSystem) DropOtherBoundingCapabilities() error {
	return f.do("drop-capability-bounding-set")
}

func (f *fakeSystem) SetGID(gid int) error {
	f.gid = gid
	return f.do("set-gid")
}

func (f *fakeSystem) SetUID(uid int) error {
	f.uid = uid
	return f.do("set-uid")
}

func (f *fakeSystem) SetNetBindServiceCapability() error {
	return f.do("set-net-bind-service-capability")
}

func (f *fakeSystem) RaiseNetBindServiceAmbient() error {
	return f.do("raise-net-bind-service-ambient")
}

func (f *fakeSystem) ReadState() (processState, error) {
	if err := f.do("read-final-state"); err != nil {
		return processState{}, err
	}
	return f.state, nil
}

func (f *fakeSystem) Exec(path string, argv, env []string) error {
	f.path = path
	f.argv = append([]string(nil), argv...)
	f.env = append([]string(nil), env...)
	return f.do("exec-original-entrypoint")
}

func TestRunPrivilegeDropSequence(t *testing.T) {
	sys := newFakeSystem()
	var audit bytes.Buffer
	args := []string{"run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"}
	env := []string{"PATH=/usr/bin:/bin", "XDG_DATA_HOME=/data"}

	if err := run(args, env, sys, &audit); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	wantCalls := []string{
		"check-root",
		"set-no-new-privileges",
		"clear-supplementary-groups",
		"preserve-permitted-capabilities",
		"drop-capability-bounding-set",
		"set-gid",
		"set-uid",
		"set-net-bind-service-capability",
		"raise-net-bind-service-ambient",
		"read-final-state",
		"exec-original-entrypoint",
	}
	if !reflect.DeepEqual(sys.calls, wantCalls) {
		t.Fatalf("calls = %v, want %v", sys.calls, wantCalls)
	}
	if sys.uid != targetUID || sys.gid != targetGID {
		t.Errorf("target IDs = %d:%d, want %d:%d", sys.uid, sys.gid, targetUID, targetGID)
	}
	if sys.path != originalEntrypoint {
		t.Errorf("exec path = %q, want %q", sys.path, originalEntrypoint)
	}
	wantArgv := append([]string{originalEntrypoint}, args...)
	if !reflect.DeepEqual(sys.argv, wantArgv) {
		t.Errorf("exec argv = %q, want %q", sys.argv, wantArgv)
	}
	if !reflect.DeepEqual(sys.env, env) {
		t.Errorf("exec env = %q, want %q", sys.env, env)
	}
	for _, text := range []string{
		"CapEff=0000000000000400",
		"CapBnd=0000000000000400",
		"CapAmb=0000000000000400",
		"NoNewPrivs=1",
		"exec " + originalEntrypoint,
	} {
		if !strings.Contains(audit.String(), text) {
			t.Errorf("audit log %q does not contain %q", audit.String(), text)
		}
	}
}

func TestRunRejectsNonRootWithoutFallback(t *testing.T) {
	sys := newFakeSystem()
	sys.euid = targetUID
	var audit bytes.Buffer

	err := run(nil, nil, sys, &audit)
	if err == nil || !strings.Contains(err.Error(), "step=check-root") {
		t.Fatalf("run() error = %v, want check-root failure", err)
	}
	if !reflect.DeepEqual(sys.calls, []string{"check-root"}) {
		t.Fatalf("calls = %v, want no operation after check-root", sys.calls)
	}
	if sys.path != "" {
		t.Fatalf("Exec called with %q for non-root input", sys.path)
	}
}

func TestRunReportsEveryFailedStep(t *testing.T) {
	steps := []string{
		"set-no-new-privileges",
		"clear-supplementary-groups",
		"preserve-permitted-capabilities",
		"drop-capability-bounding-set",
		"set-gid",
		"set-uid",
		"set-net-bind-service-capability",
		"raise-net-bind-service-ambient",
		"read-final-state",
		"exec-original-entrypoint",
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			sys := newFakeSystem()
			sys.failAt = step
			err := run(nil, nil, sys, &bytes.Buffer{})
			if !errors.Is(err, errInjected) {
				t.Fatalf("run() error = %v, want injected failure", err)
			}
			if !strings.Contains(err.Error(), "step="+step) {
				t.Fatalf("run() error = %v, want step %s", err, step)
			}
			if step != "exec-original-entrypoint" && sys.path != "" {
				t.Fatalf("Exec called after %s failed", step)
			}
		})
	}
}

func TestRunRejectsUnexpectedFinalState(t *testing.T) {
	sys := newFakeSystem()
	sys.state.CapAmb = 0

	err := run(nil, nil, sys, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "step=verify-final-state") {
		t.Fatalf("run() error = %v, want final-state failure", err)
	}
	if sys.path != "" {
		t.Fatal("Exec called with invalid final state")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errInjected
}

func TestRunDoesNotExecWithoutAuditRecord(t *testing.T) {
	sys := newFakeSystem()
	err := run(nil, nil, sys, failingWriter{})
	if !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "step=write-audit") {
		t.Fatalf("run() error = %v, want write-audit failure", err)
	}
	if sys.path != "" {
		t.Fatal("Exec called after audit write failed")
	}
}

func TestVerifyState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*processState)
	}{
		{name: "real UID remains root", mutate: func(s *processState) { s.UIDs[0] = 0 }},
		{name: "saved GID remains root", mutate: func(s *processState) { s.GIDs[3] = 0 }},
		{name: "supplementary group remains", mutate: func(s *processState) { s.Groups = []int{10} }},
		{name: "inheritable set is broad", mutate: func(s *processState) { s.CapInh |= 2 }},
		{name: "permitted set is broad", mutate: func(s *processState) { s.CapPrm |= 2 }},
		{name: "effective capability is missing", mutate: func(s *processState) { s.CapEff = 0 }},
		{name: "bounding set is broad", mutate: func(s *processState) { s.CapBnd |= 2 }},
		{name: "ambient capability is missing", mutate: func(s *processState) { s.CapAmb = 0 }},
		{name: "no-new-privileges is missing", mutate: func(s *processState) { s.NoNewPrivs = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := expectedState()
			test.mutate(&state)
			if err := verifyState(state); err == nil {
				t.Fatal("verifyState() accepted invalid state")
			}
		})
	}
}
