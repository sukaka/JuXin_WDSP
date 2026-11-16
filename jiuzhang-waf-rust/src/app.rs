use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, header},
    response::IntoResponse,
    routing::{any, get},
};
use ipnet::IpNet;
use reqwest::Url;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    access::{AccessError, AccessEvaluator, L7Action},
    client_ip,
    config::{Config, ProtectionMode},
    event::{EventLog, SecurityEvent},
    policy::{FindingAction, PolicyEngine, PolicyError},
    rate_limit::{RateLimitDecision, RateLimiter},
};

const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Debug, Default)]
pub struct Metrics {
    total: AtomicU64,
    forwarded: AtomicU64,
    observed: AtomicU64,
    blocked: AtomicU64,
    rate_limited: AtomicU64,
    upstream_errors: AtomicU64,
}

impl Metrics {
    fn increment(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            observed: self.observed.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub total: u64,
    pub forwarded: u64,
    pub observed: u64,
    pub blocked: u64,
    pub rate_limited: u64,
    pub upstream_errors: u64,
}

#[derive(Debug)]
pub struct AppState {
    config: Config,
    upstream: Url,
    client: reqwest::Client,
    access: AccessEvaluator,
    policy: PolicyEngine,
    limiter: RateLimiter,
    events: EventLog,
    metrics: Metrics,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, AppError> {
        config.validate().map_err(AppError::Configuration)?;
        let upstream = config.upstream_url().map_err(AppError::Configuration)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(config.server.request_timeout_secs))
            .build()
            .map_err(AppError::HttpClient)?;
        let access =
            AccessEvaluator::new(&config.access_control.l7_rules).map_err(AppError::Access)?;
        let policy = PolicyEngine::new(&config.policy).map_err(AppError::Policy)?;
        let limiter = RateLimiter::new(
            config.rate_limit.enabled,
            config.rate_limit.requests,
            Duration::from_secs(config.rate_limit.window_secs),
            config.rate_limit.max_tracked_ips,
        );
        let events = EventLog::create(&config.logging.events_path).map_err(AppError::EventLog)?;
        Ok(Self {
            config,
            upstream,
            client,
            access,
            policy,
            limiter,
            events,
            metrics: Metrics::default(),
        })
    }

    fn record(&self, event: SecurityEvent) {
        if let Err(error) = self.events.record(&event) {
            tracing::error!(request_id = %event.request_id, %error, "failed to persist security event");
        }
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Configuration(crate::config::ConfigError),
    #[error("cannot initialize HTTP client: {0}")]
    HttpClient(reqwest::Error),
    #[error("{0}")]
    Access(AccessError),
    #[error("{0}")]
    Policy(PolicyError),
    #[error("cannot initialize event log: {0}")]
    EventLog(std::io::Error),
}

pub fn proxy_router(state: Arc<AppState>) -> Router {
    Router::new().fallback(any(proxy_request)).with_state(state)
}

pub fn admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.metrics.snapshot())
}

async fn proxy_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let request_id = Uuid::new_v4();
    Metrics::increment(&state.metrics.total);
    let (parts, body) = request.into_parts();
    let client = client_ip::resolve(
        peer.ip(),
        &parts.headers,
        &state.config.access_control.trusted_proxies,
    );

    if !client.proxy_header_valid {
        state.record(
            SecurityEvent::new(request_id, client.ip, &parts.method, &parts.uri).decision(
                "fallback_to_peer",
                "JZN-PROXY-001",
                "invalid_forwarded_header",
                "low",
                StatusCode::OK,
            ),
        );
    }

    let l7_match = state
        .access
        .evaluate(client.ip, &parts.method, &parts.uri, &parts.headers);
    if let Some(decision) = l7_match
        .as_ref()
        .filter(|match_| match_.action == L7Action::Deny)
    {
        Metrics::increment(&state.metrics.blocked);
        state.record(
            SecurityEvent::new(request_id, client.ip, &parts.method, &parts.uri).decision(
                "blocked",
                &decision.rule_id,
                "l7_access_control",
                "medium",
                StatusCode::FORBIDDEN,
            ),
        );
        return error_response(StatusCode::FORBIDDEN, "request denied", request_id);
    }

    let allowed = contains(&state.config.access_control.allow, client.ip)
        || l7_match
            .as_ref()
            .is_some_and(|match_| match_.action == L7Action::Allow);
    if !allowed && contains(&state.config.access_control.deny, client.ip) {
        Metrics::increment(&state.metrics.blocked);
        state.record(
            SecurityEvent::new(request_id, client.ip, &parts.method, &parts.uri).decision(
                "blocked",
                "JZN-ACL-002",
                "ip_deny_list",
                "medium",
                StatusCode::FORBIDDEN,
            ),
        );
        return error_response(StatusCode::FORBIDDEN, "request denied", request_id);
    }

    if !allowed {
        match state.limiter.check(client.ip) {
            RateLimitDecision::Allowed => {}
            RateLimitDecision::Limited | RateLimitDecision::Saturated => {
                Metrics::increment(&state.metrics.rate_limited);
                state.record(
                    SecurityEvent::new(request_id, client.ip, &parts.method, &parts.uri).decision(
                        "blocked",
                        "JZN-RATE-001",
                        "request_rate",
                        "medium",
                        StatusCode::TOO_MANY_REQUESTS,
                    ),
                );
                return error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many requests",
                    request_id,
                );
            }
        }
    }

    let body = match to_bytes(body, state.config.protection.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            Metrics::increment(&state.metrics.blocked);
            state.record(
                SecurityEvent::new(request_id, client.ip, &parts.method, &parts.uri).decision(
                    "blocked",
                    "JZN-SIZE-001",
                    "request_body_limit",
                    "low",
                    StatusCode::PAYLOAD_TOO_LARGE,
                ),
            );
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large or unreadable",
                request_id,
            );
        }
    };

    if state.config.protection.mode != ProtectionMode::Off {
        let findings = state.policy.evaluate(
            &parts.method,
            &parts.uri,
            &parts.headers,
            &body,
            client.ip,
            chrono::Utc::now(),
        );
        if !findings.is_empty() {
            let protecting = state.config.protection.mode == ProtectionMode::Protect;
            let should_block = protecting
                && findings
                    .iter()
                    .any(|finding| finding.action == FindingAction::Block);
            for finding in &findings {
                let blocked = protecting && finding.action == FindingAction::Block;
                state.record(
                    SecurityEvent::new(request_id, client.ip, &parts.method, &parts.uri).decision(
                        if blocked { "blocked" } else { "observed" },
                        &finding.rule_id,
                        &finding.category,
                        &finding.severity,
                        if blocked {
                            StatusCode::FORBIDDEN
                        } else {
                            StatusCode::OK
                        },
                    ),
                );
            }
            if should_block {
                Metrics::increment(&state.metrics.blocked);
                return error_response(StatusCode::FORBIDDEN, "request blocked", request_id);
            }
            Metrics::increment(&state.metrics.observed);
        }
    }

    let Some(url) = upstream_url(&state.upstream, &parts.uri) else {
        Metrics::increment(&state.metrics.upstream_errors);
        return error_response(
            StatusCode::BAD_GATEWAY,
            "invalid upstream target",
            request_id,
        );
    };
    let mut headers = parts.headers.clone();
    strip_hop_by_hop(&mut headers);
    set_header(&mut headers, "x-forwarded-for", &client.ip.to_string());
    set_header(&mut headers, "x-real-ip", &client.ip.to_string());
    set_header(&mut headers, "x-forwarded-proto", "http");
    set_header(&mut headers, "x-request-id", &request_id.to_string());
    if let Some(host) = parts.headers.get(header::HOST) {
        headers.insert("x-forwarded-host", host.clone());
    }

    match state
        .client
        .request(parts.method.clone(), url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(upstream_response) => {
            Metrics::increment(&state.metrics.forwarded);
            let status = upstream_response.status();
            let mut response_headers = upstream_response.headers().clone();
            strip_hop_by_hop(&mut response_headers);
            let mut response = Response::new(Body::from_stream(upstream_response.bytes_stream()));
            *response.status_mut() = status;
            *response.headers_mut() = response_headers;
            finalize_response(response, request_id)
        }
        Err(error) => {
            Metrics::increment(&state.metrics.upstream_errors);
            let error = error.without_url();
            tracing::warn!(request_id = %request_id, %error, "upstream request failed");
            error_response(StatusCode::BAD_GATEWAY, "upstream unavailable", request_id)
        }
    }
}

fn contains(networks: &[IpNet], address: std::net::IpAddr) -> bool {
    networks.iter().any(|network| network.contains(&address))
}

fn upstream_url(base: &Url, uri: &Uri) -> Option<Url> {
    let suffix = uri
        .path_and_query()
        .map_or("/", |path_and_query| path_and_query.as_str());
    Url::parse(&format!(
        "{}{}",
        base.as_str().trim_end_matches('/'),
        suffix
    ))
    .ok()
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    headers.remove("proxy-connection");
}

fn set_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(HeaderName::from_static(name), value);
    }
}

fn error_response(status: StatusCode, message: &str, request_id: Uuid) -> Response<Body> {
    let response = (
        status,
        Json(serde_json::json!({
            "error": message,
            "request_id": request_id,
        })),
    )
        .into_response();
    finalize_response(response, request_id)
}

fn finalize_response(mut response: Response<Body>, request_id: Uuid) -> Response<Body> {
    set_header(
        response.headers_mut(),
        "x-request-id",
        &request_id.to_string(),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_cannot_be_replaced_by_absolute_request_target() {
        let base = Url::parse("http://127.0.0.1:3000/base").expect("base URL");
        let uri: Uri = "http://example.invalid/admin?x=1".parse().expect("URI");
        let result = upstream_url(&base, &uri).expect("upstream URL");
        assert_eq!(result.as_str(), "http://127.0.0.1:3000/base/admin?x=1");
    }
}
