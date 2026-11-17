//go:build !linux

package main

import "errors"

func newPlatformSystem() (system, error) {
	return nil, errors.New("wdsp-gateway-bind requires Linux")
}
