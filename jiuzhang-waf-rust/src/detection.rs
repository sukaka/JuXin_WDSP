use std::collections::BTreeSet;

use axum::http::{HeaderMap, Method, Uri};
use percent_encoding::percent_decode_str;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub rule_id: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
}

#[derive(Debug)]
struct Rule {
    finding: Finding,
    expression: Regex,
}

#[derive(Debug)]
pub struct DetectionEngine {
    rules: Vec<Rule>,
    scanner: Regex,
}

impl DetectionEngine {
    pub fn new() -> Result<Self, regex::Error> {
        let definitions = [
            (
                Finding {
                    rule_id: "JZN-SQL-001",
                    category: "sql_injection",
                    severity: "high",
                },
                r#"(?i)\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+(?:'[^']*'|"[^"]*"|\d+)\s*=\s*(?:'[^']*'|"[^"]*"|\d+)|\b(?:sleep|benchmark)\s*\("#,
            ),
            (
                Finding {
                    rule_id: "JZN-XSS-001",
                    category: "cross_site_scripting",
                    severity: "high",
                },
                r#"(?i)<\s*script\b|javascript\s*:|\bon(?:error|load|click|focus)\s*=|<\s*iframe\b"#,
            ),
            (
                Finding {
                    rule_id: "JZN-CMD-001",
                    category: "command_injection",
                    severity: "critical",
                },
                r"(?i)[;|&]\s*(?:id|whoami|uname|cat|curl|wget|powershell|cmd(?:\.exe)?)\b|\$\{[^}]*\b(?:ifs|path)\b|`(?:id|whoami|uname)[^`]*`",
            ),
            (
                Finding {
                    rule_id: "JZN-PATH-001",
                    category: "path_traversal",
                    severity: "high",
                },
                r"(?i)(?:\.\.[\\/])+|(?:%2e|%75){2}",
            ),
            (
                Finding {
                    rule_id: "JZN-FILE-001",
                    category: "file_inclusion",
                    severity: "high",
                },
                r"(?i)/(?:etc/(?:passwd|shadow)|proc/self/environ)\b|\b(?:php|file|data)://",
            ),
            (
                Finding {
                    rule_id: "JZN-PROTO-001",
                    category: "protocol_anomaly",
                    severity: "medium",
                },
                r"\x00",
            ),
        ];

        let rules = definitions
            .into_iter()
            .map(|(finding, pattern)| {
                Ok(Rule {
                    finding,
                    expression: Regex::new(pattern)?,
                })
            })
            .collect::<Result<Vec<_>, regex::Error>>()?;
        Ok(Self {
            rules,
            scanner: Regex::new(r"(?i)\b(?:sqlmap|nikto|masscan|acunetix|nessus)\b")?,
        })
    }

    pub fn inspect(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Vec<Finding> {
        let mut matches = BTreeSet::new();
        if matches!(method.as_str(), "TRACE" | "TRACK" | "CONNECT") {
            matches.insert(Finding {
                rule_id: "JZN-PROTO-002",
                category: "protocol_anomaly",
                severity: "medium",
            });
        }

        if let Some(path_and_query) = uri.path_and_query() {
            self.inspect_target(path_and_query.as_str(), &mut matches);
        }
        self.inspect_target(&String::from_utf8_lossy(body), &mut matches);

        for (name, value) in headers {
            if matches!(name.as_str(), "authorization" | "proxy-authorization") {
                continue;
            }
            if let Ok(value) = value.to_str() {
                self.inspect_target(
                    value.chars().take(65_536).collect::<String>().as_str(),
                    &mut matches,
                );
            }
        }

        if let Some(agent) = headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
        {
            if self.scanner.is_match(agent) {
                matches.insert(Finding {
                    rule_id: "JZN-SCAN-001",
                    category: "scanner_signature",
                    severity: "medium",
                });
            }
        }

        matches.into_iter().collect()
    }

    fn inspect_target(&self, target: &str, matches: &mut BTreeSet<Finding>) {
        let mut decoded = target.to_owned();
        for _ in 0..3 {
            for rule in &self.rules {
                if rule.expression.is_match(&decoded) {
                    matches.insert(rule.finding);
                }
            }
            let replaced = decoded.replace('+', " ");
            let next = percent_decode_str(&replaced)
                .decode_utf8_lossy()
                .into_owned();
            if next == decoded {
                break;
            }
            decoded = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> DetectionEngine {
        DetectionEngine::new().expect("valid rules")
    }

    #[test]
    fn detects_double_encoded_sql_injection() {
        let uri: Uri = "/search?q=1%2520union%2520select%2520password"
            .parse()
            .expect("URI");
        let findings = engine().inspect(&Method::GET, &uri, &HeaderMap::new(), &[]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "JZN-SQL-001")
        );
    }

    #[test]
    fn detects_script_in_request_body() {
        let uri: Uri = "/comment".parse().expect("URI");
        let findings = engine().inspect(
            &Method::POST,
            &uri,
            &HeaderMap::new(),
            br#"{"text":"<script>alert(1)</script>"}"#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.category == "cross_site_scripting")
        );
    }

    #[test]
    fn accepts_ordinary_chinese_content() {
        let uri: Uri = "/search?q=%E6%97%A5%E5%B8%B8%E8%BF%90%E7%BB%B4"
            .parse()
            .expect("URI");
        let findings = engine().inspect(
            &Method::POST,
            &uri,
            &HeaderMap::new(),
            "这是一段普通的中文文章内容。".as_bytes(),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_command_file_and_protocol_anomalies() {
        let cases = [
            (";whoami", "JZN-CMD-001"),
            ("../../etc/passwd", "JZN-PATH-001"),
            ("php://filter/convert.base64-encode", "JZN-FILE-001"),
            ("name=first\0second", "JZN-PROTO-001"),
        ];
        for (payload, expected_rule) in cases {
            let findings = engine().inspect(
                &Method::POST,
                &"/".parse().expect("URI"),
                &HeaderMap::new(),
                payload.as_bytes(),
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == expected_rule),
                "missing {expected_rule} for {payload:?}"
            );
        }

        let findings = engine().inspect(
            &Method::TRACE,
            &"/".parse().expect("URI"),
            &HeaderMap::new(),
            &[],
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "JZN-PROTO-002")
        );
    }

    #[test]
    fn detects_scanner_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "sqlmap/1.8".parse().expect("header"));
        let findings = engine().inspect(&Method::GET, &"/".parse().expect("URI"), &headers, &[]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "JZN-SCAN-001")
        );
    }
}
