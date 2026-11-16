use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddress {
    pub ip: IpAddr,
    pub proxy_header_valid: bool,
}

pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpNet]) -> ClientAddress {
    if !is_trusted(peer, trusted_proxies) {
        return ClientAddress {
            ip: peer,
            proxy_header_valid: true,
        };
    }

    let Some(raw) = headers.get("x-forwarded-for") else {
        return ClientAddress {
            ip: peer,
            proxy_header_valid: true,
        };
    };
    let Ok(raw) = raw.to_str() else {
        return invalid_proxy_header(peer);
    };
    if raw.is_empty() || raw.len() > 2048 {
        return invalid_proxy_header(peer);
    }

    let parsed: Option<Vec<IpAddr>> = raw
        .split(',')
        .map(|part| part.trim().parse::<IpAddr>().ok())
        .collect();
    let Some(mut chain) = parsed else {
        return invalid_proxy_header(peer);
    };
    if chain.is_empty() || chain.len() > 16 {
        return invalid_proxy_header(peer);
    }

    chain.push(peer);
    for address in chain.iter().rev() {
        if !is_trusted(*address, trusted_proxies) {
            return ClientAddress {
                ip: *address,
                proxy_header_valid: true,
            };
        }
    }

    ClientAddress {
        ip: chain[0],
        proxy_header_valid: true,
    }
}

fn invalid_proxy_header(peer: IpAddr) -> ClientAddress {
    ClientAddress {
        ip: peer,
        proxy_header_valid: false,
    }
}

fn is_trusted(address: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies
        .iter()
        .any(|network| network.contains(&address))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use axum::http::HeaderValue;

    use super::*;

    fn peer() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn trusted() -> Vec<IpNet> {
        vec!["127.0.0.0/8".parse().expect("valid network")]
    }

    #[test]
    fn ignores_forwarded_header_from_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8".parse().expect("header"));
        let result = resolve("192.0.2.10".parse().expect("address"), &headers, &trusted());
        assert_eq!(result.ip, "192.0.2.10".parse::<IpAddr>().expect("address"));
    }

    #[test]
    fn selects_first_untrusted_address_from_the_right() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.7, 127.0.0.2"),
        );
        let result = resolve(peer(), &headers, &trusted());
        assert_eq!(
            result.ip,
            "198.51.100.7".parse::<IpAddr>().expect("address")
        );
    }

    #[test]
    fn falls_back_to_peer_for_malformed_chain() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        let result = resolve(peer(), &headers, &trusted());
        assert_eq!(result.ip, peer());
        assert!(!result.proxy_header_valid);
    }
}
