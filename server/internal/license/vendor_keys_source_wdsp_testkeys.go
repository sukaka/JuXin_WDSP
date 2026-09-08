//go:build wdsp_testkeys

package license

import (
	"os"
	"strings"
)

// loadVendorKeysSource exists only in an explicitly tagged local/CI test build.
// It must never be used for a formal product artifact.
func loadVendorKeysSource() string {
	if v := strings.TrimSpace(os.Getenv("LICENSE_VENDOR_PUBLIC_KEY")); v != "" {
		return v
	}
	return embeddedVendorKeys
}
