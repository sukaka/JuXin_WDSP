use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::IpAddr,
    path::Path,
    sync::Mutex,
};

use axum::http::{Method, StatusCode, Uri};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub event_id: Uuid,
    pub request_id: Uuid,
    pub client_ip: IpAddr,
    pub method: String,
    pub target: String,
    pub action: String,
    pub reason: String,
    pub category: String,
    pub severity: String,
    pub status: u16,
}

impl SecurityEvent {
    pub fn new(request_id: Uuid, client_ip: IpAddr, method: &Method, uri: &Uri) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            event_id: Uuid::new_v4(),
            request_id,
            client_ip,
            method: method.to_string(),
            target: redacted_uri(uri),
            action: "observed".to_owned(),
            reason: "unspecified".to_owned(),
            category: "security".to_owned(),
            severity: "info".to_owned(),
            status: StatusCode::OK.as_u16(),
        }
    }

    pub fn decision(
        mut self,
        action: &str,
        reason: &str,
        category: &str,
        severity: &str,
        status: StatusCode,
    ) -> Self {
        self.action = action.to_owned();
        self.reason = reason.to_owned();
        self.category = category.to_owned();
        self.severity = severity.to_owned();
        self.status = status.as_u16();
        self
    }
}

#[derive(Debug)]
pub struct EventLog {
    file: Mutex<File>,
}

impl EventLog {
    pub fn create(path: &Path) -> Result<Self, std::io::Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn record(&self, event: &SecurityEvent) -> Result<(), EventError> {
        let mut file = self.file.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("event log lock was poisoned; continuing with its state");
            poisoned.into_inner()
        });
        serde_json::to_writer(&mut *file, event).map_err(EventError::Serialize)?;
        file.write_all(b"\n").map_err(EventError::Write)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum EventError {
    #[error("cannot serialize security event: {0}")]
    Serialize(serde_json::Error),
    #[error("cannot write security event: {0}")]
    Write(std::io::Error),
}

pub fn redacted_uri(uri: &Uri) -> String {
    let path = sanitize(uri.path());
    let Some(query) = uri.query() else {
        return path;
    };

    let redacted_query = query
        .split('&')
        .take(50)
        .map(|pair| {
            let key = pair.split_once('=').map_or(pair, |(key, _)| key);
            if pair.contains('=') {
                format!("{}=<redacted>", sanitize(key))
            } else {
                sanitize(key)
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{redacted_query}")
        .chars()
        .take(2048)
        .collect()
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .take(512)
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_all_query_values_and_control_characters() {
        let uri: Uri = "/login?user=alice&token=secret&next=%2Fhome"
            .parse()
            .expect("URI");
        let output = redacted_uri(&uri);
        assert_eq!(
            output,
            "/login?user=<redacted>&token=<redacted>&next=<redacted>"
        );
        assert!(!output.contains("secret"));
    }
}
