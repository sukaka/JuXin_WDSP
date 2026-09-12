package securityevents

// syslogPayload 构造安全事件的 syslog 外发 JSON payload（字段照 security_events 列名；
// request_headers/body 为入库前的脱敏内容，可安全外发）。
func syslogPayload(evt *NormalizedEvent) map[string]interface{} {
	return map[string]interface{}{
		"request_id":              evt.RequestID,
		"occurred_at":             evt.OccurredAt,
		"domain":                  evt.Host,
		"gateway_node_id":         evt.GatewayNode,
		"client_ip":               evt.ClientIP,
		"client_port":             evt.ClientPort,
		"request_method":          evt.Method,
		"request_uri":             evt.URI,
		"request_path":            evt.Path,
		"query_summary":           evt.QuerySummary,
		"http_version":            evt.HTTPVersion,
		"content_type":            evt.ContentType,
		"user_agent_summary":      evt.UserAgent,
		"referer_summary":         evt.Referer,
		"event_source":            "coraza",
		"attack_type":             evt.AttackType,
		"severity":                evt.Severity,
		"anomaly_score":           evt.AnomalyScore,
		"action":                  evt.Action,
		"response_status":         evt.ResponseStatus,
		"rule_match_count":        len(evt.Matches),
		"raw_log_reference":       evt.RawRef,
		"request_headers":         evt.RequestHeaders,
		"request_body":            evt.RequestBody,
		"request_body_truncated":  evt.RequestBodyTruncated,
		"response_headers":        evt.ResponseHeaders,
		"response_body":           evt.ResponseBody,
		"response_body_truncated": evt.ResponseBodyTruncated,
		"matches":                 evt.Matches,
	}
}
