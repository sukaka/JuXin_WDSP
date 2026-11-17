package main

import (
	"fmt"
	"io"
	"os"
)

const (
	targetUID          = 1000
	targetGID          = 1000
	capNetBindService  = 10
	expectedCapability = uint64(1 << capNetBindService)
	originalEntrypoint = "/usr/local/bin/docker-entrypoint.sh"
)

type processState struct {
	UIDs       [4]int
	GIDs       [4]int
	Groups     []int
	CapInh     uint64
	CapPrm     uint64
	CapEff     uint64
	CapBnd     uint64
	CapAmb     uint64
	NoNewPrivs int
}

type system interface {
	EffectiveUID() int
	SetNoNewPrivileges() error
	ClearSupplementaryGroups() error
	PreserveCapabilitiesAcrossSetUID() error
	DropOtherBoundingCapabilities() error
	SetGID(int) error
	SetUID(int) error
	SetNetBindServiceCapability() error
	RaiseNetBindServiceAmbient() error
	ReadState() (processState, error)
	Exec(string, []string, []string) error
}

func main() {
	if err := execute(os.Args[1:], os.Environ(), os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "wdsp-gateway-bind: %v\n", err)
		os.Exit(1)
	}
}

func execute(args, env []string, audit io.Writer) error {
	sys, err := newPlatformSystem()
	if err != nil {
		return fmt.Errorf("step=initialize-platform: %w", err)
	}
	return run(args, env, sys, audit)
}

func run(args, env []string, sys system, audit io.Writer) error {
	if euid := sys.EffectiveUID(); euid != 0 {
		return fmt.Errorf("step=check-root: effective UID is %d, want 0; refusing to run Caddy without the privilege transition", euid)
	}

	steps := []struct {
		name string
		call func() error
	}{
		{name: "set-no-new-privileges", call: sys.SetNoNewPrivileges},
		{name: "clear-supplementary-groups", call: sys.ClearSupplementaryGroups},
		{name: "preserve-permitted-capabilities", call: sys.PreserveCapabilitiesAcrossSetUID},
		{name: "drop-capability-bounding-set", call: sys.DropOtherBoundingCapabilities},
		{name: "set-gid", call: func() error { return sys.SetGID(targetGID) }},
		{name: "set-uid", call: func() error { return sys.SetUID(targetUID) }},
		{name: "set-net-bind-service-capability", call: sys.SetNetBindServiceCapability},
		{name: "raise-net-bind-service-ambient", call: sys.RaiseNetBindServiceAmbient},
	}
	for _, step := range steps {
		if err := step.call(); err != nil {
			return fmt.Errorf("step=%s: %w", step.name, err)
		}
	}

	state, err := sys.ReadState()
	if err != nil {
		return fmt.Errorf("step=read-final-state: %w", err)
	}
	if err := verifyState(state); err != nil {
		return fmt.Errorf("step=verify-final-state: %w", err)
	}
	if _, err := fmt.Fprintf(audit, "wdsp-gateway-bind: verified Uid=%d Gid=%d Groups=0 CapEff=%016X CapBnd=%016X CapAmb=%016X NoNewPrivs=1; exec %s\n",
		targetUID, targetGID, state.CapEff, state.CapBnd, state.CapAmb, originalEntrypoint); err != nil {
		return fmt.Errorf("step=write-audit: %w", err)
	}

	argv := make([]string, 1, len(args)+1)
	argv[0] = originalEntrypoint
	argv = append(argv, args...)
	if err := sys.Exec(originalEntrypoint, argv, env); err != nil {
		return fmt.Errorf("step=exec-original-entrypoint: %w", err)
	}
	return nil
}

func verifyState(state processState) error {
	wantIDs := [4]int{targetUID, targetUID, targetUID, targetUID}
	if state.UIDs != wantIDs {
		return fmt.Errorf("Uid=%v, want %v", state.UIDs, wantIDs)
	}
	if state.GIDs != wantIDs {
		return fmt.Errorf("Gid=%v, want %v", state.GIDs, wantIDs)
	}
	if len(state.Groups) != 0 {
		return fmt.Errorf("Groups=%v, want no supplementary groups", state.Groups)
	}
	for name, value := range map[string]uint64{
		"CapInh": state.CapInh,
		"CapPrm": state.CapPrm,
		"CapEff": state.CapEff,
		"CapBnd": state.CapBnd,
		"CapAmb": state.CapAmb,
	} {
		if value != expectedCapability {
			return fmt.Errorf("%s=%016X, want %016X", name, value, expectedCapability)
		}
	}
	if state.NoNewPrivs != 1 {
		return fmt.Errorf("NoNewPrivs=%d, want 1", state.NoNewPrivs)
	}
	return nil
}
