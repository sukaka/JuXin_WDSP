//go:build !wdsp_testkeys

package license

// loadVendorKeysSource is the only trust-root source in formal builds.
func loadVendorKeysSource() string {
	return embeddedVendorKeys
}
