use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::any,
};
use jiuzhang_native_waf::{
    access::{L7Action, L7RuleConfig},
    app::{AppState, admin_router, proxy_router},
    config::{Config, ProtectionMode},
    policy::{CustomRuleConfig, ExceptionConfig, RuleAction, RuleTarget},
};
use tempfile::TempDir;
use tokio::net::TcpListener;

struct TestEnvironment {
    proxy: SocketAddr,
    admin: SocketAddr,
    events_path: PathBuf,
    origin_hits: Arc<AtomicU64>,
    client: reqwest::Client,
    _storage: TempDir,
}

async fn origin(State(hits): State<Arc<AtomicU64>>, request: Request<Body>) -> impl IntoResponse {
    hits.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 2 * 1024 * 1024)
        .await
        .expect("readable origin body");
    Json(serde_json::json!({
        "method": parts.method.as_str(),
        "uri": parts.uri.to_string(),
        "body": String::from_utf8_lossy(&body),
        "request_id": parts.headers.get("x-request-id").and_then(|value| value.to_str().ok()),
        "forwarded_for": parts.headers.get("x-forwarded-for").and_then(|value| value.to_str().ok()),
    }))
}

async fn environment(mode: ProtectionMode) -> TestEnvironment {
    environment_with(mode, |_| {}).await
}

async fn environment_with(
    mode: ProtectionMode,
    configure: impl FnOnce(&mut Config),
) -> TestEnvironment {
    let origin_hits = Arc::new(AtomicU64::new(0));
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let origin_address = origin_listener.local_addr().expect("origin address");
    let origin_router = Router::new()
        .fallback(any(origin))
        .with_state(origin_hits.clone());
    tokio::spawn(async move {
        axum::serve(origin_listener, origin_router)
            .await
            .expect("origin server");
    });

    let storage = tempfile::tempdir().expect("temporary event directory");
    let events_path = storage.path().join("events.jsonl");
    let mut config = Config::default();
    config.server.upstream = format!("http://{origin_address}");
    config.protection.mode = mode;
    config.rate_limit.enabled = false;
    config.access_control.trusted_proxies = vec!["127.0.0.1/32".parse().expect("proxy network")];
    config.logging.events_path = events_path.clone();
    configure(&mut config);
    let state = Arc::new(AppState::new(config).expect("application state"));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy = proxy_listener.local_addr().expect("proxy address");
    let proxy_service =
        proxy_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_service)
            .await
            .expect("proxy server");
    });

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind admin");
    let admin = admin_listener.local_addr().expect("admin address");
    tokio::spawn(async move {
        axum::serve(admin_listener, admin_router(state))
            .await
            .expect("admin server");
    });

    TestEnvironment {
        proxy,
        admin,
        events_path,
        origin_hits,
        client: reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("test client"),
        _storage: storage,
    }
}

#[tokio::test]
async fn forwards_normal_requests_and_derives_proxy_headers() {
    let environment = environment(ProtectionMode::Protect).await;
    let response = environment
        .client
        .post(format!("http://{}/submit?token=secret", environment.proxy))
        .header("x-forwarded-for", "198.51.100.24")
        .body("ordinary payload")
        .send()
        .await
        .expect("proxy response");
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("request ID")
        .to_str()
        .expect("request ID text")
        .to_owned();
    let payload: serde_json::Value = response.json().await.expect("origin JSON");
    assert_eq!(payload["method"], "POST");
    assert_eq!(payload["uri"], "/submit?token=secret");
    assert_eq!(payload["body"], "ordinary payload");
    assert_eq!(payload["request_id"], request_id);
    assert_eq!(payload["forwarded_for"], "198.51.100.24");
}

#[tokio::test]
async fn protect_blocks_attacks_before_the_origin_and_redacts_events() {
    let environment = environment(ProtectionMode::Protect).await;
    let response = environment
        .client
        .get(format!(
            "http://{}/search?q=1%20union%20select%20password",
            environment.proxy
        ))
        .send()
        .await
        .expect("proxy response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(environment.origin_hits.load(Ordering::SeqCst), 0);

    let events = std::fs::read_to_string(&environment.events_path).expect("security events");
    assert!(events.contains("JZN-SQL-001"));
    assert!(events.contains("\"action\":\"blocked\""));
    assert!(!events.contains("union%20select"));

    let metrics: serde_json::Value = environment
        .client
        .get(format!("http://{}/metrics", environment.admin))
        .send()
        .await
        .expect("metrics response")
        .json()
        .await
        .expect("metrics JSON");
    assert_eq!(metrics["total"], 1);
    assert_eq!(metrics["blocked"], 1);
}

#[tokio::test]
async fn observe_records_attacks_but_still_forwards() {
    let environment = environment(ProtectionMode::Observe).await;
    let response = environment
        .client
        .get(format!(
            "http://{}/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            environment.proxy
        ))
        .send()
        .await
        .expect("proxy response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(environment.origin_hits.load(Ordering::SeqCst), 1);
    let events = std::fs::read_to_string(&environment.events_path).expect("security events");
    assert!(events.contains("JZN-XSS-001"));
    assert!(events.contains("\"action\":\"observed\""));
}

#[tokio::test]
async fn enforces_rate_limit() {
    let environment = environment_with(ProtectionMode::Protect, |config| {
        config.rate_limit.enabled = true;
        config.rate_limit.requests = 2;
        config.rate_limit.window_secs = 60;
    })
    .await;

    for _ in 0..2 {
        let response = environment
            .client
            .get(format!("http://{}/", environment.proxy))
            .send()
            .await
            .expect("proxy response");
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = environment
        .client
        .get(format!("http://{}/", environment.proxy))
        .send()
        .await
        .expect("rate limited response");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(environment.origin_hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn enforces_body_limit() {
    let environment = environment_with(ProtectionMode::Protect, |config| {
        config.protection.max_body_bytes = 1024;
    })
    .await;
    let response = environment
        .client
        .post(format!("http://{}/", environment.proxy))
        .body(vec![b'x'; 1025])
        .send()
        .await
        .expect("body limit response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(environment.origin_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deny_list_rejects_and_allow_list_takes_precedence() {
    let environment = environment_with(ProtectionMode::Protect, |config| {
        config.access_control.deny = vec!["203.0.113.0/24".parse().expect("deny network")];
        config.access_control.allow = vec!["203.0.113.8/32".parse().expect("allow network")];
    })
    .await;

    let blocked = environment
        .client
        .get(format!("http://{}/", environment.proxy))
        .header("x-forwarded-for", "203.0.113.66")
        .send()
        .await
        .expect("blocked response");
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    let allowed = environment
        .client
        .get(format!("http://{}/", environment.proxy))
        .header("x-forwarded-for", "203.0.113.8")
        .send()
        .await
        .expect("allowed response");
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(environment.origin_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn custom_block_rule_rejects_matching_traffic() {
    let environment = environment_with(ProtectionMode::Protect, |config| {
        config.policy.custom_rules = vec![CustomRuleConfig {
            id: "CUSTOM-BUSINESS-001".to_owned(),
            category: "business_operation".to_owned(),
            severity: "high".to_owned(),
            target: RuleTarget::Uri,
            pattern: r"(?i)dangerous-operation".to_owned(),
            action: RuleAction::Block,
            enabled: true,
        }];
    })
    .await;

    let response = environment
        .client
        .post(format!(
            "http://{}/run?action=dangerous%252Doperation",
            environment.proxy
        ))
        .send()
        .await
        .expect("custom rule response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(environment.origin_hits.load(Ordering::SeqCst), 0);
    let events = std::fs::read_to_string(&environment.events_path).expect("events");
    assert!(events.contains("CUSTOM-BUSINESS-001"));
}

#[tokio::test]
async fn custom_observe_rule_does_not_block_in_protect_mode() {
    let environment = environment_with(ProtectionMode::Protect, |config| {
        config.policy.custom_rules = vec![CustomRuleConfig {
            id: "CUSTOM-OBSERVE-001".to_owned(),
            category: "business_operation".to_owned(),
            severity: "medium".to_owned(),
            target: RuleTarget::Body,
            pattern: "review-required".to_owned(),
            action: RuleAction::Observe,
            enabled: true,
        }];
    })
    .await;

    let response = environment
        .client
        .post(format!("http://{}/run", environment.proxy))
        .body("review-required")
        .send()
        .await
        .expect("custom observe response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(environment.origin_hits.load(Ordering::SeqCst), 1);
    let events = std::fs::read_to_string(&environment.events_path).expect("events");
    assert!(events.contains("CUSTOM-OBSERVE-001"));
    assert!(events.contains("\"action\":\"observed\""));
}

#[tokio::test]
async fn disabled_rule_and_scoped_exception_change_only_their_target() {
    let disabled = environment_with(ProtectionMode::Protect, |config| {
        config.policy.disabled_rules = vec!["JZN-SQL-001".to_owned()];
    })
    .await;
    let response = disabled
        .client
        .get(format!(
            "http://{}/?q=1%20union%20select%20password",
            disabled.proxy
        ))
        .send()
        .await
        .expect("disabled rule response");
    assert_eq!(response.status(), StatusCode::OK);

    let exception = environment_with(ProtectionMode::Protect, |config| {
        config.policy.exceptions = vec![ExceptionConfig {
            rule_id: "JZN-XSS-001".to_owned(),
            path_prefix: Some("/editor".to_owned()),
            method: Some("POST".to_owned()),
            source: Some("127.0.0.1/32".parse().expect("loopback network")),
            expires_at: Some("2999-01-01T00:00:00Z".to_owned()),
        }];
    })
    .await;
    let accepted = exception
        .client
        .post(format!("http://{}/editor", exception.proxy))
        .body("<script>alert(1)</script>")
        .send()
        .await
        .expect("exception response");
    assert_eq!(accepted.status(), StatusCode::OK);
    let rejected = exception
        .client
        .post(format!("http://{}/public", exception.proxy))
        .body("<script>alert(1)</script>")
        .send()
        .await
        .expect("outside exception response");
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn l7_allow_does_not_bypass_waf() {
    let environment = environment_with(ProtectionMode::Protect, |config| {
        config.access_control.deny = vec!["127.0.0.1/32".parse().expect("loopback network")];
        config.access_control.l7_rules = vec![L7RuleConfig {
            id: "TRUSTED-PATH".to_owned(),
            enabled: true,
            priority: 10,
            methods: vec!["GET".to_owned()],
            hosts: Vec::new(),
            path_prefix: "/trusted".to_owned(),
            sources: vec!["127.0.0.1/32".parse().expect("loopback network")],
            action: L7Action::Allow,
        }];
    })
    .await;

    let allowed = environment
        .client
        .get(format!("http://{}/trusted", environment.proxy))
        .send()
        .await
        .expect("L7 allow response");
    assert_eq!(allowed.status(), StatusCode::OK);
    let denied = environment
        .client
        .get(format!("http://{}/public", environment.proxy))
        .send()
        .await
        .expect("outside L7 allow response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let attack = environment
        .client
        .get(format!(
            "http://{}/trusted?q=%3Cscript%3Ealert(1)%3C/script%3E",
            environment.proxy
        ))
        .send()
        .await
        .expect("attack through allowed path");
    assert_eq!(attack.status(), StatusCode::FORBIDDEN);
    assert_eq!(environment.origin_hits.load(Ordering::SeqCst), 1);
}
