use std::net::IpAddr;

use axum::http::{HeaderMap, Method, Uri, header};
use ipnet::IpNet;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7RuleConfig {
    pub id: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    pub priority: i32,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default = "match_all_paths")]
    pub path_prefix: String,
    #[serde(default)]
    pub sources: Vec<IpNet>,
    pub action: L7Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L7Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessMatch {
    pub rule_id: String,
    pub action: L7Action,
}

#[derive(Debug)]
struct L7Rule {
    id: String,
    priority: i32,
    methods: Vec<String>,
    hosts: Vec<String>,
    path_prefix: String,
    sources: Vec<IpNet>,
    action: L7Action,
}

#[derive(Debug)]
pub struct AccessEvaluator {
    rules: Vec<L7Rule>,
}

impl AccessEvaluator {
    pub fn new(definitions: &[L7RuleConfig]) -> Result<Self, AccessError> {
        let mut rules = Vec::new();
        let mut identifiers = std::collections::BTreeSet::new();
        for definition in definitions {
            if !definition.enabled {
                continue;
            }
            validate_identifier(&definition.id)?;
            if !identifiers.insert(definition.id.clone()) {
                return Err(AccessError::Invalid(format!(
                    "duplicate L7 rule {}",
                    definition.id
                )));
            }
            if !definition.path_prefix.starts_with('/')
                || definition.path_prefix.contains(['?', '#'])
                || definition.path_prefix.len() > 512
            {
                return Err(AccessError::Invalid(format!(
                    "rule {} has an invalid path_prefix",
                    definition.id
                )));
            }
            let methods = definition
                .methods
                .iter()
                .map(|method| {
                    let normalized = method.to_ascii_uppercase();
                    Method::from_bytes(normalized.as_bytes())
                        .map(|_| normalized)
                        .map_err(|_| {
                            AccessError::Invalid(format!(
                                "rule {} has an invalid method {method:?}",
                                definition.id
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let hosts = definition
                .hosts
                .iter()
                .map(|host| normalize_config_host(host, &definition.id))
                .collect::<Result<Vec<_>, _>>()?;
            rules.push(L7Rule {
                id: definition.id.clone(),
                priority: definition.priority,
                methods,
                hosts,
                path_prefix: definition.path_prefix.clone(),
                sources: definition.sources.clone(),
                action: definition.action,
            });
        }
        rules.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(Self { rules })
    }

    pub fn evaluate(
        &self,
        client: IpAddr,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Option<AccessMatch> {
        let request_host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(normalize_request_host)
            .unwrap_or_default();
        self.rules
            .iter()
            .find(|rule| {
                (rule.methods.is_empty() || rule.methods.iter().any(|item| item == method.as_str()))
                    && (rule.hosts.is_empty()
                        || rule
                            .hosts
                            .iter()
                            .any(|host| host_matches(host, &request_host)))
                    && uri.path().starts_with(&rule.path_prefix)
                    && (rule.sources.is_empty()
                        || rule.sources.iter().any(|network| network.contains(&client)))
            })
            .map(|rule| AccessMatch {
                rule_id: rule.id.clone(),
                action: rule.action,
            })
    }
}

#[derive(Debug, Error)]
pub enum AccessError {
    #[error("invalid L7 access policy: {0}")]
    Invalid(String),
}

fn normalize_config_host(host: &str, rule_id: &str) -> Result<String, AccessError> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.contains(['/', '@', ':', ' ', '\t'])
        || (normalized.contains('*') && !normalized.starts_with("*."))
    {
        return Err(AccessError::Invalid(format!(
            "rule {rule_id} has an invalid host {host:?}"
        )));
    }
    Ok(normalized)
}

fn normalize_request_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() || host.contains(['/', '@', ' ', '\t', '\r', '\n']) {
        return None;
    }
    let without_port = if let Some(rest) = host.strip_prefix('[') {
        let closing = rest.find(']')?;
        let address = &rest[..closing];
        let suffix = &rest[closing + 1..];
        if !suffix.is_empty() && !suffix.starts_with(':') {
            return None;
        }
        address
    } else if let Some((name, port)) = host.rsplit_once(':') {
        if port.chars().all(|character| character.is_ascii_digit()) {
            name
        } else {
            host
        }
    } else {
        host
    };
    Some(without_port.trim_end_matches('.').to_ascii_lowercase())
}

fn host_matches(rule_host: &str, request_host: &str) -> bool {
    if let Some(suffix) = rule_host.strip_prefix("*.") {
        request_host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
    } else {
        rule_host == request_host
    }
}

fn validate_identifier(id: &str) -> Result<(), AccessError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AccessError::Invalid(format!("invalid L7 rule id {id:?}")));
    }
    Ok(())
}

fn enabled_by_default() -> bool {
    true
}

fn match_all_paths() -> String {
    "/".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, priority: i32, action: L7Action) -> L7RuleConfig {
        L7RuleConfig {
            id: id.to_owned(),
            enabled: true,
            priority,
            methods: Vec::new(),
            hosts: Vec::new(),
            path_prefix: "/".to_owned(),
            sources: Vec::new(),
            action,
        }
    }

    #[test]
    fn lower_priority_value_wins() {
        let evaluator = AccessEvaluator::new(&[
            rule("SECOND", 50, L7Action::Deny),
            rule("FIRST", 10, L7Action::Allow),
        ])
        .expect("rules");
        let decision = evaluator.evaluate(
            "192.0.2.1".parse().expect("address"),
            &Method::GET,
            &"/".parse().expect("URI"),
            &HeaderMap::new(),
        );
        assert_eq!(decision.expect("match").rule_id, "FIRST");
    }

    #[test]
    fn matches_method_path_source_and_host_together() {
        let mut definition = rule("ADMIN", 10, L7Action::Deny);
        definition.methods = vec!["post".to_owned()];
        definition.path_prefix = "/admin".to_owned();
        definition.hosts = vec!["Example.COM.".to_owned()];
        definition.sources = vec!["198.51.100.0/24".parse().expect("network")];
        let evaluator = AccessEvaluator::new(&[definition]).expect("rules");
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "example.com:8080".parse().expect("host"));
        let decision = evaluator.evaluate(
            "198.51.100.8".parse().expect("address"),
            &Method::POST,
            &"/admin/users".parse().expect("URI"),
            &headers,
        );
        assert_eq!(decision.expect("match").action, L7Action::Deny);
        assert!(
            evaluator
                .evaluate(
                    "203.0.113.8".parse().expect("address"),
                    &Method::POST,
                    &"/admin/users".parse().expect("URI"),
                    &headers,
                )
                .is_none()
        );
    }

    #[test]
    fn wildcard_host_does_not_match_bare_domain() {
        let mut definition = rule("WILDCARD", 10, L7Action::Allow);
        definition.hosts = vec!["*.example.com".to_owned()];
        let evaluator = AccessEvaluator::new(&[definition]).expect("rules");
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "www.example.com".parse().expect("host"));
        assert!(
            evaluator
                .evaluate(
                    "192.0.2.1".parse().expect("address"),
                    &Method::GET,
                    &"/".parse().expect("URI"),
                    &headers,
                )
                .is_some()
        );
        headers.insert(header::HOST, "example.com".parse().expect("host"));
        assert!(
            evaluator
                .evaluate(
                    "192.0.2.1".parse().expect("address"),
                    &Method::GET,
                    &"/".parse().expect("URI"),
                    &headers,
                )
                .is_none()
        );
    }

    #[test]
    fn invalid_or_disabled_rules_do_not_run() {
        let mut definition = rule("BROKEN", 10, L7Action::Deny);
        definition.path_prefix = "admin".to_owned();
        assert!(AccessEvaluator::new(&[definition]).is_err());

        let mut disabled = rule("DISABLED", 10, L7Action::Deny);
        disabled.enabled = false;
        let evaluator = AccessEvaluator::new(&[disabled]).expect("empty rules");
        assert!(
            evaluator
                .evaluate(
                    "192.0.2.1".parse().expect("address"),
                    &Method::GET,
                    &"/".parse().expect("URI"),
                    &HeaderMap::new(),
                )
                .is_none()
        );
    }
}
