package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func parseProcessStatus(input io.Reader) (processState, error) {
	var state processState
	required := []string{"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
	seen := make(map[string]bool, len(required))

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], strings.TrimSpace(parts[1])
		wanted := false
		for _, name := range required {
			if key == name {
				wanted = true
				break
			}
		}
		if !wanted {
			continue
		}

		var err error
		switch key {
		case "Uid":
			state.UIDs, err = parseIDs(value)
		case "Gid":
			state.GIDs, err = parseIDs(value)
		case "Groups":
			state.Groups, err = parseGroups(value)
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			var capability uint64
			capability, err = strconv.ParseUint(value, 16, 64)
			switch key {
			case "CapInh":
				state.CapInh = capability
			case "CapPrm":
				state.CapPrm = capability
			case "CapEff":
				state.CapEff = capability
			case "CapBnd":
				state.CapBnd = capability
			case "CapAmb":
				state.CapAmb = capability
			}
		case "NoNewPrivs":
			state.NoNewPrivs, err = strconv.Atoi(value)
		}
		if err != nil {
			return processState{}, fmt.Errorf("parse %s value %q: %w", key, value, err)
		}
		seen[key] = true
	}
	if err := scanner.Err(); err != nil {
		return processState{}, fmt.Errorf("read process status: %w", err)
	}
	for _, key := range required {
		if !seen[key] {
			return processState{}, fmt.Errorf("missing %s", key)
		}
	}
	return state, nil
}

func parseIDs(value string) ([4]int, error) {
	var ids [4]int
	fields := strings.Fields(value)
	if len(fields) != len(ids) {
		return ids, fmt.Errorf("got %d IDs, want 4", len(fields))
	}
	for i, field := range fields {
		id, err := strconv.Atoi(field)
		if err != nil {
			return ids, err
		}
		ids[i] = id
	}
	return ids, nil
}

func parseGroups(value string) ([]int, error) {
	fields := strings.Fields(value)
	groups := make([]int, len(fields))
	for i, field := range fields {
		group, err := strconv.Atoi(field)
		if err != nil {
			return nil, err
		}
		groups[i] = group
	}
	return groups, nil
}
