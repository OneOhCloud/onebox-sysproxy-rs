use crate::{Autoproxy, Error, Result, Sysproxy};
use log::debug;
use std::process::Command;
use std::str::from_utf8;

// ---------------------------------------------------------------------------
// networksetup command wrapper
// ---------------------------------------------------------------------------

/// Run a `networksetup` subcommand, returning its stdout on success.
///
/// `networksetup` writes its diagnostics (e.g. "** Error: The parameters were
/// not valid.") to **stdout**, not stderr, and exits non-zero. Earlier code
/// ignored the exit status and parsed stdout regardless, so a bad service name
/// surfaced as a misleading `failed to parse string \`port\`` instead of the
/// real reason. We check the status and surface both streams.
fn run_networksetup(args: &[&str]) -> Result<String> {
    let out = Command::new("networksetup").args(args).output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let detail: Vec<&str> = [stdout.trim(), stderr.trim()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        return Err(Error::Command(format!(
            "networksetup {:?} exited {:?}: {}",
            args,
            out.status.code(),
            detail.join(" | ")
        )));
    }
    Ok(stdout.into_owned())
}

// ---------------------------------------------------------------------------
// Active network service resolution
// ---------------------------------------------------------------------------

/// Resolve the active default-route interface to its `networksetup` **service**
/// name (e.g. `Wi-Fi`, or whatever the user renamed it to).
///
/// `route -n get default` gives the BSD device; `-listnetworkserviceorder`
/// maps device → service name. The service name — not the hardware-port label
/// from `-listallhardwareports` — is the only token `networksetup` accepts.
/// The two coincide only for an unrenamed built-in adapter; they diverge when
/// a service is renamed, when the OS auto-creates a "<name> 2", and for USB
/// adapters whose hardware port is "Ethernet Adapter (enX)" while the service
/// carries its own name. Feeding the hardware-port label to `-setwebproxy` /
/// `-setdnsservers` then fails with exit 4 / exit 8 on such machines.
///
/// Offline-safe: uses the routing table, not a UDP probe to a public IP.
pub fn active_network_service() -> Result<String> {
    let iface = default_route_interface()?;
    let order = run_networksetup(&["-listnetworkserviceorder"])?;
    service_for_device(&order, &iface)
        .ok_or_else(|| Error::Command(format!("no network service maps to interface {iface}")))
}

fn default_route_interface() -> Result<String> {
    let out = Command::new("route").args(["-n", "get", "default"]).output()?;
    let stdout = from_utf8(&out.stdout).or(Err(Error::ParseStr("route".into())))?;
    stdout
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("interface:")
                .map(|s| s.trim().to_string())
        })
        .ok_or(Error::NetworkInterface)
}

/// Map a BSD device (`en0`) to its network service name by parsing
/// `networksetup -listnetworkserviceorder`. Pure string work, unit-tested.
/// The format is paired lines:
///
/// ```text
/// (3) Wi-Fi
/// (Hardware Port: Wi-Fi, Device: en0)
/// ```
///
/// A disabled service uses `(*)` in place of the index; the device cell can be
/// empty (e.g. Tailscale), which must never match a real interface.
fn service_for_device(serviceorder: &str, device: &str) -> Option<String> {
    let mut pending: Option<String> = None;
    for line in serviceorder.lines().map(str::trim) {
        if let Some(detail) = line.strip_prefix("(Hardware Port:") {
            let dev = detail
                .rsplit("Device:")
                .next()
                .map(|d| d.trim_end_matches(')').trim())
                .unwrap_or("");
            if !dev.is_empty() && dev == device && let Some(service) = pending.take() {
                return Some(service);
            }
            pending = None;
        } else if line.starts_with('(') {
            // Service header: "(N) Name" or "(*) Name". The index paren is
            // always first, so taking everything past it preserves a service
            // name that itself contains parentheses.
            pending = line.find(')').map(|c| line[c + 1..].trim().to_string());
        }
    }
    None
}

/// Active service, falling back to the first listed service when the default
/// route can't be resolved (e.g. offline during shutdown).
fn resolve_service() -> Result<String> {
    active_network_service().or_else(|e| {
        debug!("route-based service detection failed: {e:?}; falling back to first service");
        first_network_service()
    })
}

fn first_network_service() -> Result<String> {
    let out = run_networksetup(&["-listallnetworkservices"])?;
    out.lines()
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or(Error::NetworkInterface)
}

/// Enabled network services (skips the header tip line and `*`-prefixed
/// disabled services). Every returned name is a valid `networksetup` argument.
fn list_all_services() -> Result<Vec<String>> {
    let out = run_networksetup(&["-listallnetworkservices"])?;
    Ok(out
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(ToString::to_string)
        .collect())
}

// ---------------------------------------------------------------------------
// Proxy get/set
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum ProxyType {
    Http,
    Https,
    Socks,
}

impl ProxyType {
    fn target(self) -> &'static str {
        match self {
            ProxyType::Http => "webproxy",
            ProxyType::Https => "securewebproxy",
            ProxyType::Socks => "socksfirewallproxy",
        }
    }
}

fn get_proxy(proxy_type: ProxyType, service: &str) -> Result<Sysproxy> {
    let target = format!("-get{}", proxy_type.target());
    let stdout = run_networksetup(&[target.as_str(), service])?;
    let enable = parse(&stdout, "Enabled:") == "Yes";
    let host = parse(&stdout, "Server:").to_string();
    // On valid output Port is always numeric ("0" when unset); only reachable
    // because run_networksetup already rejected error stdout via exit status.
    let port = parse(&stdout, "Port:").parse().unwrap_or(0);
    Ok(Sysproxy {
        enable,
        host,
        port,
        bypass: String::new(),
    })
}

fn set_proxy(proxy: &Sysproxy, proxy_type: ProxyType, service: &str) -> Result<()> {
    let set_target = format!("-set{}", proxy_type.target());
    let port = proxy.port.to_string();
    run_networksetup(&[set_target.as_str(), service, proxy.host.as_str(), port.as_str()])?;
    set_proxy_state(proxy_type, service, proxy.enable)
}

fn set_proxy_state(proxy_type: ProxyType, service: &str, enable: bool) -> Result<()> {
    let target = format!("-set{}state", proxy_type.target());
    run_networksetup(&[target.as_str(), service, if enable { "on" } else { "off" }])?;
    Ok(())
}

fn get_bypass(service: &str) -> Result<String> {
    let stdout = run_networksetup(&["-getproxybypassdomains", service])?;
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(","))
}

/// Disable the system proxy on **every** service whose configured proxy server
/// matches `host`. Clears a proxy the caller set even if the active interface
/// changed since it was applied (e.g. Wi-Fi → Ethernet), avoiding a stale proxy
/// left behind on the previously-active service.
pub fn clear_proxy(host: &str) -> Result<()> {
    for service in list_all_services()? {
        for kind in [ProxyType::Http, ProxyType::Https, ProxyType::Socks] {
            let current = get_proxy(kind, &service)?;
            if current.enable && current.host == host {
                set_proxy_state(kind, &service, false)?;
            }
        }
    }
    Ok(())
}

impl Sysproxy {
    /// Gets the current system proxy settings on the active service.
    pub fn get_system_proxy() -> Result<Sysproxy> {
        let service = resolve_service()?;

        let mut socks = get_proxy(ProxyType::Socks, &service)?;
        let http = get_proxy(ProxyType::Http, &service)?;
        let https = get_proxy(ProxyType::Https, &service)?;
        socks.bypass = get_bypass(&service)?;

        if !socks.enable {
            if http.enable {
                socks.enable = true;
                socks.host = http.host;
                socks.port = http.port;
            } else if https.enable {
                socks.enable = true;
                socks.host = https.host;
                socks.port = https.port;
            }
        }

        Ok(socks)
    }

    /// Sets the system proxy on the active service. Returns an error if any
    /// `networksetup` call fails (e.g. an unresolvable service), so callers
    /// fail fast instead of believing a silently-rejected proxy was applied.
    pub fn set_system_proxy(&self) -> Result<()> {
        let service = resolve_service()?;
        set_proxy(self, ProxyType::Socks, &service)?;
        set_proxy(self, ProxyType::Http, &service)?;
        set_proxy(self, ProxyType::Https, &service)?;
        self.set_bypass(&service)?;
        Ok(())
    }

    pub fn get_http(service: &str) -> Result<Sysproxy> {
        get_proxy(ProxyType::Http, service)
    }

    pub fn get_https(service: &str) -> Result<Sysproxy> {
        get_proxy(ProxyType::Https, service)
    }

    pub fn get_socks(service: &str) -> Result<Sysproxy> {
        get_proxy(ProxyType::Socks, service)
    }

    pub fn get_bypass(service: &str) -> Result<String> {
        get_bypass(service)
    }

    pub fn set_http(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Http, service)
    }

    pub fn set_https(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Https, service)
    }

    pub fn set_socks(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Socks, service)
    }

    pub fn set_bypass(&self, service: &str) -> Result<()> {
        let domains: Vec<&str> = self.bypass.split(',').filter(|s| !s.is_empty()).collect();
        let mut args = vec!["-setproxybypassdomains", service];
        args.extend(domains);
        run_networksetup(&args)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Auto-proxy (PAC)
// ---------------------------------------------------------------------------

impl Autoproxy {
    /// Gets the current auto-proxy (PAC) settings.
    pub fn get_auto_proxy() -> Result<Autoproxy> {
        let service = resolve_service()?;
        let stdout = run_networksetup(&["-getautoproxyurl", &service])?;
        let enable = parse(&stdout, "Enabled:") == "Yes";
        let url = strip_str(parse(&stdout, "URL:"));
        // macOS returns "(null)" when no PAC URL is configured.
        let url = if url == "(null)" { "" } else { url };
        Ok(Autoproxy {
            enable,
            url: url.to_string(),
        })
    }

    /// Sets the auto-proxy (PAC) configuration.
    pub fn set_auto_proxy(&self) -> Result<()> {
        let service = resolve_service()?;
        let url = if self.url.is_empty() {
            "\"\""
        } else {
            self.url.as_str()
        };
        run_networksetup(&["-setautoproxyurl", &service, url])?;
        run_networksetup(&[
            "-setautoproxystate",
            &service,
            if self.enable { "on" } else { "off" },
        ])?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Return the trimmed value following `key` on its line (`""` if absent).
fn parse<'a>(text: &'a str, key: &str) -> &'a str {
    match text.find(key) {
        Some(idx) => {
            let rest = &text[idx + key.len()..];
            let value = rest.split('\n').next().unwrap_or(rest);
            value.trim()
        }
        None => "",
    }
}

fn strip_str(text: &str) -> &str {
    text.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::service_for_device;

    // Mirror of a real `-listnetworkserviceorder` dump: a USB ethernet whose
    // service name ("AX88179A") differs from its hardware-port label, the
    // built-in Wi-Fi, and a Tailscale service with an empty device cell.
    const ORDER: &str = "An asterisk (*) denotes that a network service is disabled.\n\
(1) AX88179A\n\
(Hardware Port: AX88179A, Device: en6)\n\
\n\
(2) Thunderbolt Bridge\n\
(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\
\n\
(3) Wi-Fi\n\
(Hardware Port: Wi-Fi, Device: en0)\n\
\n\
(4) Tailscale\n\
(Hardware Port: io.tailscale.ipn.macsys, Device: )\n";

    #[test]
    fn maps_builtin_wifi_device_to_service() {
        assert_eq!(service_for_device(ORDER, "en0").as_deref(), Some("Wi-Fi"));
    }

    #[test]
    fn maps_usb_adapter_to_service_name_not_hardware_port() {
        // `-listallhardwareports` labels this device "Ethernet Adapter (en6)";
        // only the service name "AX88179A" works with networksetup. This is the
        // case the old hardware-port lookup got wrong.
        assert_eq!(service_for_device(ORDER, "en6").as_deref(), Some("AX88179A"));
    }

    #[test]
    fn maps_renamed_wifi_service() {
        // Hardware port stays "Wi-Fi" but the service was renamed, so
        // `-setwebproxy "Wi-Fi"` / `-setdnsservers "Wi-Fi"` return exit 4/8.
        let order = "An asterisk (*) denotes that a network service is disabled.\n\
(1) 我的无线\n\
(Hardware Port: Wi-Fi, Device: en0)\n";
        assert_eq!(service_for_device(order, "en0").as_deref(), Some("我的无线"));
    }

    #[test]
    fn empty_device_cell_never_matches() {
        assert_eq!(service_for_device(ORDER, ""), None);
    }

    #[test]
    fn unknown_device_returns_none() {
        assert_eq!(service_for_device(ORDER, "en9"), None);
    }

    #[test]
    fn service_name_with_parentheses_preserved() {
        let order = "header\n(2) Home (5GHz)\n(Hardware Port: Wi-Fi, Device: en0)\n";
        assert_eq!(
            service_for_device(order, "en0").as_deref(),
            Some("Home (5GHz)")
        );
    }
}
