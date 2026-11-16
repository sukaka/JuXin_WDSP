use std::{collections::BTreeSet, net::IpAddr};

use axum::http::{HeaderMap, Method, Uri};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

use crate::detection::DetectionEngine;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub disabled_rules: Vec<String>,
    pub custom_rules: Vec<CustomRuleConfig>,
    pub exceptions: Vec<ExceptionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRuleConfig {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub target: RuleTarget,
    pub pattern: String,
    pub action: RuleAction,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    Uri,
    Body,
    Headers,
    UserAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Observe,
    Block,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionConfig {
    pub rule_id: String,
    pub path_prefix: Option<String>,
    pub method: Option<String>,
    pub source: Option<IpNet>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingAction {
    Observe,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFinding {
    pub rule_id: String,
    pub category: String,
    pub severity: String,
    pub action: FindingAction,
}

#[derive(Debug)]
struct CustomRule {
    id: String,
    category: String,
    severity: String,
    target: RuleTarget,
    expression: Regex,
    action: FindingAction,
}

#[derive(Debug)]
struct Exception {
    rule_id: String,
    path_prefix: Option<String>,
    method: Option<Method>,
    source: Option<IpNet>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct PolicyEngine {
    detector: DetectionEngine,
    disabled: BTreeSet<String>,
    custom: Vec<CustomRule>,
    exceptions: Vec<Exception>,
}

impl PolicyEngine {
    pub fn new(config: &PolicyConfig) -> Result<Self, PolicyError> {
        let detector = DetectionEngine::new().map_err(PolicyError::BuiltInRules)?;
        let mut disabled = BTreeSet::new();
        for id in &config.disabled_rules {
            validate_id(id)?;
            if !disabled.insert(id.clone()) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate disabled rule {id}"
                )));
            }
        }

        let mut custom = Vec::new();
        let mut custom_ids = BTreeSet::new();
        for definition in &config.custom_rules {
            validate_id(&definition.id)?;
            validate_label(&definition.category, "category")?;
            if !matches!(
                definition.severity.as_str(),
                "low" | "medium" | "high" | "critical"
            ) {
                return Err(PolicyError::Invalid(format!(
                    "rule {} has an invalid severity",
                    definition.id
                )));
            }
            if !custom_ids.insert(definition.id.clone()) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate custom rule {}",
                    definition.id
                )));
            }
            if definition.pattern.is_empty() || definition.pattern.len() > 512 {
                return Err(PolicyError::Invalid(format!(
                    "rule {} pattern must contain 1 to 512 bytes",
                    definition.id
                )));
            }
            if !definition.enabled {
                continue;
            }
            let expression = Regex::new(&definition.pattern).map_err(|error| {
                PolicyError::Invalid(format!(
                    "rule {} pattern is invalid: {error}",
                    definition.id
                ))
            })?;
            custom.push(CustomRule {
                id: definition.id.clone(),
                category: definition.category.clone(),
                severity: definition.severity.clone(),
                target: definition.target,
                expression,
                action: match definition.action {
                    RuleAction::Observe => FindingAction::Observe,
                    RuleAction::Block => FindingAction::Block,
                },
            });
        }

        let exceptions = config
            .exceptions
            .iter()
            .map(compile_exception)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            detector,
            disabled,
            custom,
            exceptions,
        })
    }

    pub fn evaluate(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
        client: IpAddr,
        now: DateTime<Utc>,
    ) -> Vec<PolicyFinding> {
        let mut findings: Vec<PolicyFinding> = self
            .detector
            .inspect(method, uri, headers, body)
            .into_iter()
            .map(|finding| PolicyFinding {
                rule_id: finding.rule_id.to_owned(),
                category: finding.category.to_owned(),
                severity: finding.severity.to_owned(),
                action: FindingAction::Block,
            })
            .collect();

        for rule in &self.custom {
            let target = target_text(rule.target, uri, headers, body);
            if decoded_forms(&target)
                .iter()
                .any(|form| rule.expression.is_match(form))
            {
                findings.push(PolicyFinding {
                    rule_id: rule.id.clone(),
                    category: rule.category.clone(),
                    severity: rule.severity.clone(),
                    action: rule.action,
                });
            }
        }

        findings
            .into_iter()
            .filter(|finding| !self.disabled.contains(&finding.rule_id))
            .filter(|finding| {
                !self.exceptions.iter().any(|exception| {
                    exception_applies(exception, finding, method, uri, client, now)
                })
            })
            .collect()
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid WAF policy: {0}")]
    Invalid(String),
    #[error("cannot initialize built-in rules: {0}")]
    BuiltInRules(regex::Error),
}

fn compile_exception(config: &ExceptionConfig) -> Result<Exception, PolicyError> {
    if config.rule_id != "*" {
        validate_id(&config.rule_id)?;
    }
    if let Some(path) = &config.path_prefix {
        if !path.starts_with('/') || path.contains(['?', '#']) || path.len() > 512 {
            return Err(PolicyError::Invalid(
                "exception path_prefix must be an absolute path without query or fragment"
                    .to_owned(),
            ));
        }
    }
    let method = config
        .method
        .as_deref()
        .map(|method| {
            Method::from_bytes(method.to_ascii_uppercase().as_bytes())
                .map_err(|_| PolicyError::Invalid(format!("invalid exception method {method}")))
        })
        .transpose()?;
    let expires_at = config
        .expires_at
        .as_deref()
        .map(|timestamp| {
            DateTime::parse_from_rfc3339(timestamp)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| {
                    PolicyError::Invalid(format!("invalid exception timestamp {timestamp}"))
                })
        })
        .transpose()?;
    Ok(Exception {
        rule_id: config.rule_id.clone(),
        path_prefix: config.path_prefix.clone(),
        method,
        source: config.source,
        expires_at,
    })
}

fn exception_applies(
    exception: &Exception,
    finding: &PolicyFinding,
    method: &Method,
    uri: &Uri,
    client: IpAddr,
    now: DateTime<Utc>,
) -> bool {
    if exception.rule_id != "*" && exception.rule_id != finding.rule_id {
        return false;
    }
    if exception
        .path_prefix
        .as_deref()
        .is_some_and(|prefix| !uri.path().starts_with(prefix))
    {
        return false;
    }
    if exception
        .method
        .as_ref()
        .is_some_and(|allowed| allowed != method)
    {
        return false;
    }
    if exception
        .source
        .as_ref()
        .is_some_and(|network| !network.contains(&client))
    {
        return false;
    }
    if exception
        .expires_at
        .as_ref()
        .is_some_and(|expires| expires <= &now)
    {
        return false;
    }
    true
}

fn target_text(target: RuleTarget, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> String {
    match target {
        RuleTarget::Uri => uri
            .path_and_query()
            .map_or_else(|| uri.path().to_owned(), |value| value.as_str().to_owned()),
        RuleTarget::Body => String::from_utf8_lossy(body).into_owned(),
        RuleTarget::UserAgent => headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        RuleTarget::Headers => {
            let mut combined = String::new();
            for (name, value) in headers {
                if matches!(
                    name.as_str(),
                    "authorization" | "proxy-authorization" | "cookie"
                ) {
                    continue;
                }
                if let Ok(value) = value.to_str() {
                    let remaining = 65_536usize.saturating_sub(combined.len());
                    if remaining == 0 {
                        break;
                    }
                    combined.push_str(name.as_str());
                    combined.push_str(": ");
                    combined.push_str(&value.chars().take(remaining).collect::<String>());
                    combined.push('\n');
                }
            }
            combined
        }
    }
}

fn decoded_forms(target: &str) -> Vec<String> {
    let mut forms = vec![target.to_owned()];
    for _ in 0..3 {
        let previous = forms.last().expect("initial form exists");
        let replaced = previous.replace('+', " ");
        let next = percent_decode_str(&replaced)
            .decode_utf8_lossy()
            .into_owned();
        if next == *previous {
            break;
        }
        forms.push(next);
    }
    forms
}

fn validate_id(id: &str) -> Result<(), PolicyError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(PolicyError::Invalid(format!(
            "rule id must contain 1 to 64 ASCII letters, digits, '-' or '_': {id:?}"
        )));
    }
    Ok(())
}

fn validate_label(value: &str, field: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(PolicyError::Invalid(format!(
            "invalid custom rule {field}: {value:?}"
        )));
    }
    Ok(())
}

fn enabled_by_default() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom_rule(id: &str, target: RuleTarget, action: RuleAction) -> CustomRuleConfig {
        CustomRuleConfig {
            id: id.to_owned(),
            category: "application_specific".to_owned(),
            severity: "high".to_owned(),
            target,
            pattern: r"(?i)dangerous-operation".to_owned(),
            action,
            enabled: true,
        }
    }

    fn engine(config: PolicyConfig) -> PolicyEngine {
        PolicyEngine::new(&config).expect("valid policy")
    }

    fn evaluate(config: PolicyConfig, uri: &str, body: &[u8]) -> Vec<PolicyFinding> {
        engine(config).evaluate(
            &Method::POST,
            &uri.parse().expect("URI"),
            &HeaderMap::new(),
            body,
            "192.0.2.10".parse().expect("address"),
            Utc::now(),
        )
    }

    #[test]
    fn custom_rule_detects_encoded_uri() {
        let config = PolicyConfig {
            custom_rules: vec![custom_rule(
                "CUSTOM-001",
                RuleTarget::Uri,
                RuleAction::Block,
            )],
            ..PolicyConfig::default()
        };
        let findings = evaluate(config, "/run?value=dangerous%252Doperation", &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "CUSTOM-001");
        assert_eq!(findings[0].action, FindingAction::Block);
    }

    #[test]
    fn custom_observe_rule_never_requests_blocking() {
        let config = PolicyConfig {
            custom_rules: vec![custom_rule(
                "CUSTOM-002",
                RuleTarget::Body,
                RuleAction::Observe,
            )],
            ..PolicyConfig::default()
        };
        let findings = evaluate(config, "/run", b"dangerous-operation");
        assert_eq!(findings[0].action, FindingAction::Observe);
    }

    #[test]
    fn disabled_built_in_rule_is_removed() {
        let config = PolicyConfig {
            disabled_rules: vec!["JZN-SQL-001".to_owned()],
            ..PolicyConfig::default()
        };
        let findings = evaluate(config, "/?q=1%20union%20select%20password", &[]);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "JZN-SQL-001")
        );
    }

    #[test]
    fn exception_only_applies_to_its_scope() {
        let config = PolicyConfig {
            exceptions: vec![ExceptionConfig {
                rule_id: "JZN-XSS-001".to_owned(),
                path_prefix: Some("/editor".to_owned()),
                method: Some("POST".to_owned()),
                source: Some("192.0.2.0/24".parse().expect("network")),
                expires_at: None,
            }],
            ..PolicyConfig::default()
        };
        assert!(evaluate(config.clone(), "/editor", b"<script>alert(1)</script>").is_empty());
        assert!(!evaluate(config, "/public", b"<script>alert(1)</script>").is_empty());
    }

    #[test]
    fn expired_exception_does_not_suppress() {
        let config = PolicyConfig {
            exceptions: vec![ExceptionConfig {
                rule_id: "*".to_owned(),
                path_prefix: None,
                method: None,
                source: None,
                expires_at: Some("2000-01-01T00:00:00Z".to_owned()),
            }],
            ..PolicyConfig::default()
        };
        assert!(!evaluate(config, "/", b"<script>alert(1)</script>").is_empty());
    }

    #[test]
    fn rejects_duplicate_ids_and_invalid_regex() {
        let duplicate = PolicyConfig {
            custom_rules: vec![
                custom_rule("SAME", RuleTarget::Uri, RuleAction::Block),
                custom_rule("SAME", RuleTarget::Body, RuleAction::Block),
            ],
            ..PolicyConfig::default()
        };
        assert!(PolicyEngine::new(&duplicate).is_err());

        let mut invalid = PolicyConfig::default();
        invalid.custom_rules.push(CustomRuleConfig {
            pattern: "(".to_owned(),
            ..custom_rule("BROKEN", RuleTarget::Uri, RuleAction::Block)
        });
        assert!(PolicyEngine::new(&invalid).is_err());
    }

    #[test]
    fn rejects_ambiguous_exception_fields() {
        let config = PolicyConfig {
            exceptions: vec![ExceptionConfig {
                rule_id: "JZN-SQL-001".to_owned(),
                path_prefix: Some("relative/path".to_owned()),
                method: None,
                source: None,
                expires_at: None,
            }],
            ..PolicyConfig::default()
        };
        assert!(PolicyEngine::new(&config).is_err());
    }

    #[test]
    fn disabled_custom_rule_is_not_compiled_or_evaluated() {
        let mut definition = custom_rule("DISABLED", RuleTarget::Uri, RuleAction::Block);
        definition.enabled = false;
        definition.pattern = "(".to_owned();
        let config = PolicyConfig {
            custom_rules: vec![definition],
            ..PolicyConfig::default()
        };
        assert!(evaluate(config, "/?x=dangerous-operation", &[]).is_empty());
    }
}
