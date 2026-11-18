package accesslogs

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

func validateAuditFilter(f *ListFilter, query url.Values) error {
	f.RequestID = strings.TrimSpace(query.Get("request_id"))
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{name: "domain", value: f.Domain, max: 255},
		{name: "method", value: f.Method, max: 16},
		{name: "uri", value: f.URI, max: 2048},
		{name: "waf_action", value: f.WAFAction, max: 32},
		{name: "request_id", value: f.RequestID, max: 64},
	} {
		if len(field.value) > field.max {
			return fmt.Errorf("%s 长度不能超过%d字节", field.name, field.max)
		}
	}
	if f.ClientIP != "" {
		if _, err := netip.ParseAddr(f.ClientIP); err != nil {
			return fmt.Errorf("client_ip 必须是合法IP地址")
		}
	}
	if f.Status != nil && (*f.Status < 100 || *f.Status > 599) {
		return fmt.Errorf("status 必须在100..599之间")
	}
	if f.StartTime != nil && f.EndTime != nil && !f.EndTime.After(*f.StartTime) {
		return fmt.Errorf("end_time 必须晚于 start_time")
	}
	if value := strings.TrimSpace(query.Get("application_id")); value != "" {
		applicationID, err := uuid.Parse(value)
		if err != nil {
			return fmt.Errorf("application_id 必须是合法UUID")
		}
		f.ApplicationID = &applicationID
	}
	f.TraceID = strings.TrimSpace(query.Get("trace_id"))
	if f.TraceID != "" && !validAuditTraceID(f.TraceID) {
		return fmt.Errorf("trace_id 必须是32位小写hex且不能全为零")
	}
	f.IdentityFingerprint = strings.TrimSpace(query.Get("identity_fingerprint"))
	if len(f.IdentityFingerprint) > 128 {
		return fmt.Errorf("identity_fingerprint 长度不能超过128字节")
	}
	f.RuleID = strings.TrimSpace(query.Get("rule_id"))
	if len(f.RuleID) > 128 {
		return fmt.Errorf("rule_id 长度不能超过128字节")
	}
	f.EndpointKey = strings.TrimSpace(query.Get("endpoint_key"))
	f.FieldPath = strings.TrimSpace(query.Get("field_path"))
	f.DataType = strings.TrimSpace(query.Get("data_type"))
	f.Direction = strings.ToUpper(strings.TrimSpace(query.Get("direction")))
	if len(f.EndpointKey) > 600 || len(f.FieldPath) > 512 || len(f.DataType) > 64 {
		return fmt.Errorf("API或敏感字段筛选条件过长")
	}
	if f.Direction != "" && f.Direction != "REQUEST" && f.Direction != "RESPONSE" {
		return fmt.Errorf("direction 仅支持 REQUEST 或 RESPONSE")
	}
	if raw := strings.TrimSpace(query.Get("request_ids")); raw != "" {
		if f.RequestID != "" || len(raw) > 6500 {
			return fmt.Errorf("request_ids 不能与 request_id 混用，且最多100个请求ID")
		}
		seen := make(map[string]bool)
		for _, value := range strings.Split(raw, ",") {
			value = strings.TrimSpace(value)
			if value == "" || len(value) > 64 || seen[value] {
				return fmt.Errorf("request_ids 包含空值、重复值或超长ID")
			}
			seen[value] = true
			f.RequestIDs = append(f.RequestIDs, value)
		}
		if len(f.RequestIDs) > 100 {
			return fmt.Errorf("request_ids 最多支持100个请求")
		}
	}
	return nil
}

func validAuditTraceID(value string) bool {
	if len(value) != 32 || value == strings.Repeat("0", 32) {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func parseAuditTime(value, name string) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("%s 必须是RFC3339时间", name)
	}
	return &parsed, nil
}
