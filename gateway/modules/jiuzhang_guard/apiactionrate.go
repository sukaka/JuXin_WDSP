package jiuzhang_guard

import (
	"fmt"
	"regexp"
	"strings"
)

const maxAPIEndpointActionBytes = 64

var apiEndpointActionPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func validateAPIEndpointActions(actions map[string]string) error {
	for endpointKey, action := range actions {
		if strings.TrimSpace(endpointKey) == "" {
			return fmt.Errorf("api_endpoint_actions: endpoint_key must be non-empty")
		}
		normalized := strings.ToUpper(strings.TrimSpace(action))
		if len(normalized) > maxAPIEndpointActionBytes || !apiEndpointActionPattern.MatchString(normalized) {
			return fmt.Errorf("api_endpoint_actions[%q]: invalid action", endpointKey)
		}
	}
	return nil
}
