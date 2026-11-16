use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use ipnet::IpNet;
use reqwest::Url;
use serde::Deserialize;
use thiserror::Error;

use crate::{access::L7RuleConfig, policy::PolicyConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtectionMode {
    Off,
    Observe,
    Protect,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub upstream: String,
    pub request_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:18080".parse().expect("valid default address"),
            admin_listen: "127.0.0.1:19090".parse().expect("valid default address"),
            upstream: "http://127.0.0.1:3000".to_owned(),
            request_timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectionConfig {
    pub mode: ProtectionMode,
    pub max_body_bytes: usize,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            mode: ProtectionMode::Observe,
            max_body_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessControlConfig {
    pub trusted_proxies: Vec<IpNet>,
    pub allow: Vec<IpNet>,
    pub deny: Vec<IpNet>,
    pub l7_rules: Vec<L7RuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests: u64,
    pub window_secs: u64,
    pub max_tracked_ips: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests: 120,
            window_secs: 60,
            max_tracked_ips: 10_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub events_path: PathBuf,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            events_path: PathBuf::from("var/security-events.jsonl"),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub protection: ProtectionConfig,
    pub access_control: AccessControlConfig,
    pub policy: PolicyConfig,
    pub rate_limit: RateLimitConfig,
    pub logging: LoggingConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let source = fs::read_to_string(path).map_err(ConfigError::Read)?;
        let config: Self = toml::from_str(&source).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.listen == self.server.admin_listen {
            return Err(ConfigError::Validation(
                "server.listen and server.admin_listen must differ".to_owned(),
            ));
        }
        if !(1..=300).contains(&self.server.request_timeout_secs) {
            return Err(ConfigError::Validation(
                "server.request_timeout_secs must be between 1 and 300".to_owned(),
            ));
        }
        if !(1024..=100 * 1024 * 1024).contains(&self.protection.max_body_bytes) {
            return Err(ConfigError::Validation(
                "protection.max_body_bytes must be between 1024 and 104857600".to_owned(),
            ));
        }
        if self.rate_limit.enabled
            && (self.rate_limit.requests == 0
                || self.rate_limit.window_secs == 0
                || self.rate_limit.max_tracked_ips == 0)
        {
            return Err(ConfigError::Validation(
                "enabled rate limiting requires positive requests, window_secs and max_tracked_ips"
                    .to_owned(),
            ));
        }
        if self.logging.events_path.as_os_str().is_empty() {
            return Err(ConfigError::Validation(
                "logging.events_path cannot be empty".to_owned(),
            ));
        }
        self.upstream_url().map(|_| ())
    }

    pub fn upstream_url(&self) -> Result<Url, ConfigError> {
        let url = Url::parse(&self.server.upstream)
            .map_err(|error| ConfigError::Validation(format!("invalid upstream: {error}")))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(ConfigError::Validation(
                "upstream must be an absolute HTTP or HTTPS URL".to_owned(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ConfigError::Validation(
                "upstream user information is not allowed".to_owned(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ConfigError::Validation(
                "upstream cannot contain a query or fragment".to_owned(),
            ));
        }
        Ok(url)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration: {0}")]
    Read(std::io::Error),
    #[error("cannot parse configuration: {0}")]
    Parse(toml::de::Error),
    #[error("invalid configuration: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().expect("valid defaults");
    }

    #[test]
    fn rejects_non_http_upstream() {
        let mut config = Config::default();
        config.server.upstream = "file:///tmp/origin".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_shared_listeners() {
        let mut config = Config::default();
        config.server.admin_listen = config.server.listen;
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let result: Result<Config, _> = toml::from_str("unexpected = true");
        assert!(result.is_err());
    }
}
