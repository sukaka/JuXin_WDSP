//go:build !linux

package main

func maybeDropPrivileges() error            { return nil }
func maybeDropHealthcheckPrivileges() error { return nil }
