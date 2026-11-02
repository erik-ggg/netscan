//! Public IP and ISP discovery. Failures are silent (offline is fine).

use serde::Deserialize;
use std::time::Duration;

#[derive(Default)]
pub struct Internet {
    pub public_ip: Option<String>,
    pub isp: Option<String>,
}

#[derive(Deserialize)]
struct IpInfo {
    ip: Option<String>,
    org: Option<String>,
}

pub async fn fetch() -> Internet {
    let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(3)).build() else {
        return Internet::default();
    };
    let info = async {
        client.get("https://ipinfo.io/json").send().await.ok()?.json::<IpInfo>().await.ok()
    };
    let plain = async {
        for url in ["https://api.ipify.org", "https://ifconfig.me/ip"] {
            if let Ok(r) = client.get(url).send().await
                && let Ok(t) = r.text().await
                && t.trim().parse::<std::net::IpAddr>().is_ok()
            {
                return Some(t.trim().to_string());
            }
        }
        None
    };
    let (info, ip) = tokio::join!(info, plain);
    let isp = info.as_ref().and_then(|i| i.org.clone()).map(|o| {
        // "AS3352 Telefonica de Espana" -> drop the ASN prefix.
        let name = match o.split_once(' ') {
            Some((a, rest)) if a.starts_with("AS") => rest,
            _ => &o,
        };
        super::vendor::pretty_vendor(name)
    });
    Internet { public_ip: ip.or(info.and_then(|i| i.ip)), isp }
}
