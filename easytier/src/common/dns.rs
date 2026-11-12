use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::Context;
use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, Record};
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{Resolver, TokioResolver};
use once_cell::sync::Lazy;
use tokio::net::lookup_host;

use super::error::Error;

/// Jay: no built-in public resolvers. Upstream added two fixed public DNS servers here, so a
/// host name that the system resolver could not look up was also sent, in plain UDP, to third
/// parties the user never chose. Only the system's own name servers are used now.
pub fn get_default_resolver_config() -> ResolverConfig {
    ResolverConfig::from_name_servers(Vec::new())
}

pub static ALLOW_USE_SYSTEM_DNS_RESOLVER: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(true));

pub static RESOLVER: Lazy<Arc<Resolver<TokioRuntimeProvider>>> =
    Lazy::new(|| {
        let system_cfg = read_system_conf();
        let mut cfg = get_default_resolver_config();
        let mut opt = ResolverOpts::default();
        if let Ok(s) = system_cfg {
            for ns in s.0.name_servers() {
                cfg.add_name_server(ns.clone());
            }
            opt = s.1;
        }
        opt.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let builder = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default())
            .with_options(opt);
        // build() only fails when a TLS transport is compiled in; this build has none.
        Arc::new(builder.build().expect("plain UDP/TCP resolver builds"))
    });

/// The first string of the first TXT record among `answers`. Since hickory 0.26 a lookup returns
/// every answer record (a CNAME chain can come first), so pick the TXT records out by type.
fn first_txt_string(answers: &[Record]) -> Option<String> {
    answers.iter().find_map(|r| match &r.data {
        RData::TXT(txt) => txt
            .txt_data
            .first()
            .map(|s| String::from_utf8_lossy(s).into_owned()),
        _ => None,
    })
}

pub async fn resolve_txt_record(domain_name: &str) -> Result<String, Error> {
    let r = RESOLVER.clone();
    let response = r
        .txt_lookup(domain_name)
        .await
        .with_context(|| format!("txt_lookup failed, domain_name: {}", domain_name))?;

    let txt_data = first_txt_string(response.answers())
        .with_context(|| format!("no txt record found, domain_name: {}", domain_name))?;
    tracing::info!(?txt_data, ?domain_name, "get txt record");

    Ok(txt_data)
}

pub async fn socket_addrs(
    url: &url::Url,
    default_port_number: impl Fn() -> Option<u16>,
) -> Result<Vec<SocketAddr>, Error> {
    let host = url.host().ok_or(Error::InvalidUrl(url.to_string()))?;
    let port = url
        .port()
        .or_else(default_port_number)
        .ok_or(Error::InvalidUrl(url.to_string()))?;

    // if host is an ip address, return it directly
    match host {
        url::Host::Ipv4(ip) => return Ok(vec![SocketAddr::new(std::net::IpAddr::V4(ip), port)]),
        url::Host::Ipv6(ip) => return Ok(vec![SocketAddr::new(std::net::IpAddr::V6(ip), port)]),
        _ => {}
    }
    let host = host.to_string();

    if ALLOW_USE_SYSTEM_DNS_RESOLVER.load(std::sync::atomic::Ordering::Relaxed) {
        let socket_addr = format!("{}:{}", host, port);
        match lookup_host(socket_addr).await {
            Ok(a) => {
                let a = a.collect();
                tracing::debug!(?a, "system dns lookup done");
                return Ok(a);
            }
            Err(e) => {
                tracing::error!(?e, "system dns lookup failed");
            }
        }
    }

    // use hickory_resolver
    let ret = RESOLVER.lookup_ip(&host).await.with_context(|| {
        format!(
            "hickory dns lookup_ip failed, host: {}, port: {}",
            host, port
        )
    })?;
    Ok(ret
        .iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use guarden::defer;

    #[tokio::test]
    async fn test_socket_addrs() {
        let url = url::Url::parse("tcp://github-ci-test.easytier.cn:80").unwrap();
        let addrs = socket_addrs(&url, || Some(80)).await.unwrap();
        assert_eq!(2, addrs.len(), "addrs: {:?}", addrs);
        println!("addrs: {:?}", addrs);

        ALLOW_USE_SYSTEM_DNS_RESOLVER.store(false, std::sync::atomic::Ordering::Relaxed);
        defer!(
            ALLOW_USE_SYSTEM_DNS_RESOLVER.store(true, std::sync::atomic::Ordering::Relaxed);
        );
        let addrs = socket_addrs(&url, || Some(80)).await.unwrap();
        assert_eq!(2, addrs.len(), "addrs: {:?}", addrs);
        println!("addrs2: {:?}", addrs);
    }

    #[test]
    fn jay_txt_answer_skips_other_records() {
        use hickory_resolver::proto::rr::{
            Name,
            rdata::{CNAME, TXT},
        };
        let name = Name::from_ascii("peers.example.").unwrap();
        let target = Name::from_ascii("real.example.").unwrap();
        let answers = vec![
            Record::from_rdata(name.clone(), 60, RData::CNAME(CNAME(target.clone()))),
            Record::from_rdata(target, 60, RData::TXT(TXT::new(vec!["tcp://a:1".into()]))),
        ];
        assert_eq!(first_txt_string(&answers).as_deref(), Some("tcp://a:1"));
        assert_eq!(first_txt_string(&answers[..1]), None);
    }

    #[test]
    fn jay_no_builtin_public_resolvers() {
        assert!(get_default_resolver_config().name_servers().is_empty());
    }

    #[tokio::test]
    async fn socket_addrs_preserves_explicit_zero_port() {
        let cases = [
            ("ws://127.0.0.1:0", 80, 0),
            ("wss://127.0.0.1:0", 443, 0),
            ("ws://127.0.0.1", 80, 80),
            ("wss://127.0.0.1", 443, 443),
        ];

        for (raw_url, default_port, expected_port) in cases {
            let url = url::Url::parse(raw_url).unwrap();
            let addrs = socket_addrs(&url, || Some(default_port)).await.unwrap();
            assert_eq!(
                addrs,
                vec![SocketAddr::from(([127, 0, 0, 1], expected_port))]
            );
        }
    }
}
