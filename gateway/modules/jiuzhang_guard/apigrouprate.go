package jiuzhang_guard

import (
	"fmt"
	"regexp"
	"strings"
)

const maxAPIEndpointGroupBytes = 64

var apiEndpointGroupPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func validateAPIEndpointGroups(groups map[string]map[string][]string) error {
	for applicationID, endpoints := range groups {
		if strings.TrimSpace(applicationID) == "" {
			return fmt.Errorf("api_endpoint_groups: application_id must be non-empty")
		}
		for endpointKey, groupCodes := range endpoints {
			if strings.TrimSpace(endpointKey) == "" {
				return fmt.Errorf("api_endpoint_groups: endpoint_key must be non-empty")
			}
			seen := make(map[string]struct{}, len(groupCodes))
			for _, groupCode := range groupCodes {
				normalized := strings.ToUpper(strings.TrimSpace(groupCode))
				if len(normalized) > maxAPIEndpointGroupBytes || !apiEndpointGroupPattern.MatchString(normalized) {
					return fmt.Errorf("api_endpoint_groups[%q][%q]: invalid group_code", applicationID, endpointKey)
				}
				if _, duplicate := seen[normalized]; duplicate {
					return fmt.Errorf("api_endpoint_groups[%q][%q]: duplicate group_code", applicationID, endpointKey)
				}
				seen[normalized] = struct{}{}
			}
		}
	}
	return nil
}
