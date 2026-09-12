package apiassets

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// discoveryEndpointKey is the runtime contract: policy/model maps and gateway
// lookups use METHOD + normalized path. Ownership is deliberately kept out of
// this value; discoveryScopeKey supplies the database identity instead.
func discoveryEndpointKey(method, path, _host, _scopeKey string, _applicationID, _domainID *uuid.UUID, _protocol string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + strings.TrimSpace(path)
}

func normalizeDiscoveryHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(host, ".")
}

// discoveryScopeKey is used only by the in-memory repository. SQL uses the
// equivalent tuple in migration 000137.
func discoveryScopeKey(method, path, host, scopeKey string, applicationID, domainID, bindingID *uuid.UUID, protocol string) string {
	if bindingID != nil {
		scopeKey = bindingID.String()
	}
	protocol = protocolOrDefault(strings.ToUpper(strings.TrimSpace(protocol)))
	parts := []string{
		endpointKeyPart(uuidString(applicationID)),
		endpointKeyPart(uuidString(domainID)),
		endpointKeyPart(strings.TrimSpace(scopeKey)),
		endpointKeyPart(normalizeDiscoveryHost(host)),
		endpointKeyPart(strings.ToUpper(strings.TrimSpace(method))),
		endpointKeyPart(strings.TrimSpace(path)),
		endpointKeyPart(protocol),
	}
	return strings.Join(parts, "")
}

func endpointKeyPart(value string) string {
	return fmt.Sprintf("%d:%s;", len(value), value)
}

func uuidString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
