//go:build !linux

package main

func maybeDropPrivileges() error { return nil }
