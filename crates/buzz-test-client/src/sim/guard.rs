//! Target guard: the load generator's own wall against the wrong relay.
//!
//! Every address tenant_sim connects to (websocket, media upload, git) is a
//! [`Target`], and only [`TargetGuard::check_url`] builds one. A target must
//! be a literal IP address, never a name, so nothing is ever resolved. It
//! must sit inside the run's allow list and not on its deny list; the deny
//! list wins. No flag or environment variable turns the guard off.
//!
//! The HTTP client built here ignores proxies, follows no redirect and
//! refuses to resolve names. Git gets the same treatment in `git.rs`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

/// Narrowest IPv4 prefix accepted on the allow list. A wider entry would
/// switch the allow wall off (`0.0.0.0/0` allows everything).
pub const MIN_ALLOW_PREFIX_V4: u8 = 8;
/// Narrowest IPv6 prefix accepted on the allow list.
pub const MIN_ALLOW_PREFIX_V6: u8 = 32;

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is the IPv4 address it
/// maps to. Nothing else is converted: `::a.b.c.d` stays IPv6.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// A strict IPv4 literal: four decimal parts, 0-255, no leading zeros, ASCII
/// only. Refuses `127.1`, `0x7f.0.0.1`, `0177.0.0.1` and `2130706433`, which
/// a URL parser would quietly turn into an address.
fn strict_ipv4(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for p in &parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
    }
    s.parse().ok()
}

/// A strict IPv6 literal (no brackets, no zone id).
fn strict_ipv6(s: &str) -> Option<Ipv6Addr> {
    if s.is_empty()
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    {
        return None;
    }
    s.parse().ok()
}

/// A literal IP address in either family, canonicalized.
pub fn parse_ip_literal(s: &str) -> Option<IpAddr> {
    if let Some(v4) = strict_ipv4(s) {
        return Some(IpAddr::V4(v4));
    }
    strict_ipv6(s).map(|v6| canonical(IpAddr::V6(v6)))
}

/// An address block. A bare address is a single-address block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d/n`, `a.b.c.d`, `x::y/n` or `x::y`. Host bits must be
    /// zero, and an IPv4-mapped block becomes the IPv4 block it maps to.
    pub fn parse(s: &str) -> Result<Self> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    bail!("{s:?}: bad prefix length");
                }
                if p.len() > 1 && p.starts_with('0') {
                    bail!("{s:?}: bad prefix length");
                }
                (
                    a,
                    Some(
                        p.parse::<u8>()
                            .map_err(|_| anyhow!("{s:?}: bad prefix length"))?,
                    ),
                )
            }
            None => (s, None),
        };
        let ip = if let Some(v4) = strict_ipv4(addr) {
            IpAddr::V4(v4)
        } else if let Some(v6) = strict_ipv6(addr) {
            IpAddr::V6(v6)
        } else {
            bail!("{s:?}: not a literal IP address or block");
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            bail!("{s:?}: prefix longer than {max}");
        }
        let cidr = match ip {
            IpAddr::V6(v6) if prefix >= 96 && v6.to_ipv4_mapped().is_some() => Cidr {
                net: IpAddr::V4(v6.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED)),
                prefix: prefix - 96,
            },
            _ => Cidr { net: ip, prefix },
        };
        if cidr.masked(cidr.net) != cidr.net {
            bail!(
                "{s:?}: host bits set; the block starts at {}/{}",
                cidr.masked(cidr.net),
                cidr.prefix
            );
        }
        Ok(cidr)
    }

    fn masked(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                IpAddr::V6(Ipv6Addr::from(bits & mask))
            }
        }
    }

    /// Whether `ip` (same family) is inside this block.
    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.net.is_ipv4() && self.masked(ip) == self.net
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

/// Parse a deny-list file: one address or block per line, `#` comments and
/// blank lines ignored. Any other line refuses the whole file.
pub fn parse_deny_list(text: &str) -> Result<Vec<Cidr>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let entry = line.split('#').next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        out.push(Cidr::parse(entry).with_context(|| format!("deny list line {}", i + 1))?);
    }
    Ok(out)
}

/// The run's allow and deny lists.
#[derive(Debug, Clone)]
pub struct TargetGuard {
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
}

impl TargetGuard {
    /// Build the guard from `--allow-cidr` values and the `--deny-list` file.
    /// Both are required; an empty deny-list file is allowed, a missing one
    /// is not.
    pub fn from_args(allow: &[String], deny_list: Option<&Path>) -> Result<Self> {
        if allow.is_empty() {
            bail!("--allow-cidr is required (repeatable; no default)");
        }
        let deny_list = deny_list
            .ok_or_else(|| anyhow!("--deny-list <file> is required (the file may be empty)"))?;
        let text = std::fs::read_to_string(deny_list)
            .with_context(|| format!("read deny list {}", deny_list.display()))?;
        let allow = allow
            .iter()
            .map(|s| Cidr::parse(s).with_context(|| format!("--allow-cidr {s:?}")))
            .collect::<Result<Vec<_>>>()?;
        Self::new(allow, parse_deny_list(&text)?)
    }

    /// Build the guard from parsed lists. Refuses an empty allow list and any
    /// allow entry wider than [`MIN_ALLOW_PREFIX_V4`] / [`MIN_ALLOW_PREFIX_V6`].
    pub fn new(allow: Vec<Cidr>, deny: Vec<Cidr>) -> Result<Self> {
        if allow.is_empty() {
            bail!("the allow list is empty");
        }
        for c in &allow {
            let floor = if c.net.is_ipv4() {
                MIN_ALLOW_PREFIX_V4
            } else {
                MIN_ALLOW_PREFIX_V6
            };
            if c.prefix < floor {
                bail!(
                    "--allow-cidr {c} is wider than /{floor}; that would switch the allow list off"
                );
            }
        }
        Ok(Self { allow, deny })
    }

    /// Refuse `ip` unless it is inside the allow list and on no deny entry.
    pub fn check_ip(&self, ip: IpAddr) -> Result<()> {
        let ip = canonical(ip);
        if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
            bail!("{ip} is not a unicast address");
        }
        if let Some(d) = self.deny.iter().find(|d| d.contains(ip)) {
            bail!("{ip} is on the deny list ({d})");
        }
        if !self.allow.iter().any(|a| a.contains(ip)) {
            bail!("{ip} is outside the allow list");
        }
        Ok(())
    }

    /// Check `raw` and return the only kind of value a connection accepts.
    ///
    /// `raw` must be `scheme://IP[:port][path]` with the scheme in `schemes`,
    /// an IPv4 literal or a bracketed IPv6 literal, no userinfo, query or
    /// fragment, and nothing a parser would rewrite. The WHATWG parser in
    /// `url` must then agree on the same address and port.
    pub fn check_url(&self, raw: &str, schemes: &[&str]) -> Result<Target> {
        let refuse = |why: &str| anyhow!("target {raw:?} refused: {why}");
        if !raw.is_ascii() {
            return Err(refuse("non-ASCII characters"));
        }
        if raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\' || b == b'%')
        {
            return Err(refuse("whitespace, control characters, '\\' or '%'"));
        }
        let (scheme, rest) = raw.split_once("://").ok_or_else(|| refuse("no scheme"))?;
        if !schemes.contains(&scheme) {
            return Err(refuse(&format!("scheme must be one of {schemes:?}")));
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if path.contains(['?', '#', '@']) {
            return Err(refuse("query, fragment or '@' after the address"));
        }
        if authority.contains('@') {
            return Err(refuse("userinfo ('@')"));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or_else(|| refuse("unclosed '['"))?;
            let port = match after {
                "" => None,
                p => Some(
                    p.strip_prefix(':')
                        .ok_or_else(|| refuse("junk after ']'"))?,
                ),
            };
            let ip = strict_ipv6(h).ok_or_else(|| refuse("not an IPv6 literal"))?;
            (IpAddr::V6(ip), port)
        } else {
            let (h, port) = match authority.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            };
            let ip = strict_ipv4(h).ok_or_else(|| refuse("not a literal IP address"))?;
            (IpAddr::V4(ip), port)
        };
        let port = match port {
            None => None,
            Some(p) => {
                if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(refuse("bad port"));
                }
                match p.parse::<u16>() {
                    Ok(n) if n > 0 && !(p.len() > 1 && p.starts_with('0')) => Some(n),
                    _ => return Err(refuse("bad port")),
                }
            }
        };
        let url = url::Url::parse(raw).map_err(|e| refuse(&e.to_string()))?;
        let parsed_ip = match url.host() {
            Some(url::Host::Ipv4(v4)) => IpAddr::V4(v4),
            Some(url::Host::Ipv6(v6)) => IpAddr::V6(v6),
            _ => return Err(refuse("the URL parser does not see an IP address")),
        };
        // `url` drops a port equal to the scheme's default, so compare the
        // effective port rather than the written one.
        let effective = url.port_or_known_default();
        if effective.is_none() {
            return Err(refuse("no port"));
        }
        if parsed_ip != host
            || !url.username().is_empty()
            || url.password().is_some()
            || (port.is_none() && url.port().is_some())
            || (port.is_some() && effective != port)
        {
            return Err(refuse("the URL parser reads a different address"));
        }
        self.check_ip(host).map_err(|e| refuse(&e.to_string()))?;
        Ok(Target {
            raw: raw.to_string(),
            url,
            ip: canonical(host),
        })
    }
}

/// A connection target that passed [`TargetGuard::check_url`]. Its fields
/// are private, so nothing else can build one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    raw: String,
    url: url::Url,
    ip: IpAddr,
}

impl Target {
    /// The URL exactly as checked.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The checked address (IPv4-mapped IPv6 shown as IPv4).
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The same address and port with `path` (starting with `/`) appended to
    /// the checked URL's path. Refuses anything that would change the host.
    pub fn join(&self, path: &str) -> Result<Target> {
        if !path.starts_with('/') || path.contains(['?', '#', '@', '\\', '%']) || !path.is_ascii() {
            bail!("path {path:?} refused");
        }
        let raw = format!("{}{path}", self.raw.trim_end_matches('/'));
        let url = url::Url::parse(&raw).with_context(|| format!("join {path:?}"))?;
        if url.host() != self.url.host()
            || url.port() != self.url.port()
            || url.scheme() != self.url.scheme()
        {
            bail!("path {path:?} changes the target");
        }
        Ok(Target {
            raw,
            url,
            ip: self.ip,
        })
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// A resolver that resolves nothing. Targets are literal addresses, so the
/// HTTP client never needs DNS; if a name ever reached it, it fails here.
struct NoDns;

impl reqwest::dns::Resolve for NoDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name = name.as_str().to_string();
        Box::pin(async move {
            Err::<reqwest::dns::Addrs, _>(
                format!("tenant_sim resolves no names (asked for {name:?})").into(),
            )
        })
    }
}

/// The only HTTP client tenant_sim uses: no proxy (the environment's proxy
/// variables and system settings are ignored), no redirects, no DNS. Only
/// [`http_client`] builds one, and media upload takes nothing else.
#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
}

impl HttpClient {
    /// The underlying client, for building requests to a checked [`Target`].
    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }
}

/// Build the guarded [`HttpClient`].
pub fn http_client(timeout: Duration) -> Result<HttpClient> {
    Ok(HttpClient {
        inner: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(NoDns))
            .timeout(timeout)
            .build()?,
    })
}

/// The OS errors that mean the generator itself ran out of something: its
/// open files (EMFILE, ENFILE), its local ports (EADDRNOTAVAIL), its socket
/// buffers (ENOBUFS). A connect that fails on one of these never reached
/// the relay: it is the generator's own fault, never the relay's.
#[cfg(target_os = "linux")]
const LOCAL_EXHAUSTION: [i32; 4] = [24, 23, 99, 105];
#[cfg(not(target_os = "linux"))]
const LOCAL_EXHAUSTION: [i32; 4] = [24, 23, 49, 55];

/// Whether `err`, or anything it was caused by, is the generator running
/// out of files, ports or buffers ([`LOCAL_EXHAUSTION`]).
pub fn is_local_exhaustion(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut at: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = at {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::AddrNotAvailable
                || io
                    .raw_os_error()
                    .is_some_and(|c| LOCAL_EXHAUSTION.contains(&c))
            {
                return true;
            }
        }
        at = e.source();
    }
    false
}

/// [`is_local_exhaustion`] on an error already written out as text (a
/// connect error that was formatted on its way up): its `(os error N)`.
pub fn text_is_local_exhaustion(text: &str) -> bool {
    LOCAL_EXHAUSTION
        .iter()
        .any(|c| text.contains(&format!("(os error {c})")))
}

/// Loopback servers and a child-process runner shared by the guard tests
/// here and in `git.rs` / `media.rs`.
#[cfg(test)]
pub(crate) mod testsrv {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A server on `bind` that counts connections and answers every request
    /// with `response` (after reading its headers and body).
    pub struct Server {
        pub addr: SocketAddr,
        accepts: Arc<AtomicUsize>,
    }

    impl Server {
        pub fn start(bind: &str, response: String) -> Server {
            Server::start_after(bind, response, std::time::Duration::ZERO)
        }

        /// [`Server::start`], but each answer waits `delay` first: a slow
        /// remote.
        pub fn start_after(bind: &str, response: String, delay: std::time::Duration) -> Server {
            let listener = TcpListener::bind(bind).expect("bind test server");
            let addr = listener.local_addr().expect("addr");
            let accepts = Arc::new(AtomicUsize::new(0));
            let count = accepts.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    count.fetch_add(1, Ordering::SeqCst);
                    let response = response.clone();
                    std::thread::spawn(move || {
                        let mut reader = BufReader::new(stream);
                        let mut len = 0usize;
                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            let lower = line.to_ascii_lowercase();
                            if let Some(v) = lower.strip_prefix("content-length:") {
                                len = v.trim().parse().unwrap_or(0);
                            }
                            if line == "\r\n" {
                                break;
                            }
                        }
                        let mut body = vec![0u8; len];
                        let _ = reader.read_exact(&mut body);
                        std::thread::sleep(delay);
                        let mut stream = reader.into_inner();
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    });
                }
            });
            Server { addr, accepts }
        }

        pub fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }

        /// `http://<addr>` with IPv6 bracketed.
        pub fn http(&self) -> String {
            format!("http://{}", self.addr)
        }
    }

    /// `302` to `location`.
    pub fn redirect_to(location: &str) -> String {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    /// A plain response with a JSON body.
    pub fn status(code: u16, body: &str) -> String {
        format!(
            "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// A `Command` for a child a test starts: nothing of this process's
    /// environment but `PATH`, `HOME` and `TMPDIR` (each only when set) and
    /// `LC_ALL=C`. A row adds the values it names with `.env`, after this, so
    /// no credential of whoever runs the tests reaches a child, whatever its
    /// name.
    pub fn test_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear().env("LC_ALL", "C");
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd
    }

    /// Env var telling a re-executed test binary which test is the child.
    pub const CHILD_VAR: &str = "TENANT_SIM_GUARD_CHILD";

    /// Whether this process is the child for `test`.
    pub fn is_child(test: &str) -> bool {
        std::env::var(CHILD_VAR).as_deref() == Ok(test)
    }

    /// Run `test` (its libtest path) in a fresh copy of this test binary with
    /// [`test_command`]'s set and `env` added, and require that it passed and
    /// printed `CHILD_OK <test>`.
    /// Without the sentinel a filter that matched nothing would look like a
    /// pass.
    pub fn run_child(test: &str, env: &[(&str, String)]) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = test_command(exe);
        cmd.args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_VAR, test);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("run child test");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains(&format!("CHILD_OK {test}")),
            "child {test} failed: {}\nstdout:\n{stdout}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// [`run_child`] with the child's open-file soft limit at `nofile`
    /// (`ulimit -n` in a shell that then execs it): a child can run out of
    /// files without starving this process or its other tests.
    pub fn run_child_with_nofile(test: &str, nofile: u32) {
        let exe = std::env::current_exe().expect("current_exe");
        let out = test_command("/bin/sh")
            .args([
                "-c",
                &format!("ulimit -n {nofile} && exec \"$0\" \"$@\""),
                &exe.to_string_lossy(),
                test,
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_VAR, test)
            .output()
            .expect("run child test");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains(&format!("CHILD_OK {test}")),
            "child {test} failed: {}\nstdout:\n{stdout}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A fresh directory under the system temp dir.
    pub fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenant-sim-guard-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        dir
    }

    /// Every proxy variable pointed at `proxy`.
    pub fn proxy_env(proxy: &str) -> Vec<(&'static str, String)> {
        [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ]
        .into_iter()
        .map(|k| (k, proxy.to_string()))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testsrv::{self, Server};
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vectors {
        allow: Vec<String>,
        deny: Vec<String>,
        accept: Vec<Accept>,
        refuse: Vec<Refuse>,
        bad_cidr: Vec<String>,
        good_cidr: Vec<(String, String)>,
    }

    #[derive(serde::Deserialize)]
    struct Accept {
        url: String,
        schemes: Vec<String>,
        ip: String,
    }

    #[derive(serde::Deserialize)]
    struct Refuse {
        url: String,
        why: String,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../../../../perf/guard_vectors.json")).expect("vectors")
    }

    fn cidrs(list: &[String]) -> Vec<Cidr> {
        list.iter().map(|s| Cidr::parse(s).expect(s)).collect()
    }

    fn vector_guard(v: &Vectors) -> TargetGuard {
        TargetGuard::new(cidrs(&v.allow), cidrs(&v.deny)).expect("guard")
    }

    const ALL_SCHEMES: [&str; 4] = ["ws", "wss", "http", "https"];

    #[test]
    fn accepts_literal_addresses_inside_the_allow_list() {
        let v = vectors();
        let g = vector_guard(&v);
        for a in &v.accept {
            let schemes: Vec<&str> = a.schemes.iter().map(String::as_str).collect();
            let t = g
                .check_url(&a.url, &schemes)
                .unwrap_or_else(|e| panic!("{} should pass: {e:#}", a.url));
            assert_eq!(t.as_str(), a.url);
            assert_eq!(t.ip().to_string(), a.ip, "{}", a.url);
        }
    }

    #[test]
    fn refuses_names_tricky_literals_and_listed_addresses() {
        let v = vectors();
        let g = vector_guard(&v);
        for r in &v.refuse {
            assert!(
                g.check_url(&r.url, &ALL_SCHEMES).is_err(),
                "{:?} ({}) should be refused",
                r.url,
                r.why
            );
        }
    }

    #[test]
    fn the_deny_list_wins_over_the_allow_list() {
        let g = TargetGuard::new(
            cidrs(&["198.51.100.0/24".into()]),
            cidrs(&["198.51.100.7".into()]),
        )
        .expect("guard");
        let err = g
            .check_url("http://198.51.100.7:3030", &["http"])
            .expect_err("denied");
        assert!(format!("{err:#}").contains("deny list"), "{err:#}");
        g.check_url("http://198.51.100.8:3030", &["http"])
            .expect("allowed neighbour");
    }

    #[test]
    fn allow_entries_must_be_narrow_and_well_formed() {
        let v = vectors();
        for s in &v.bad_cidr {
            let r = Cidr::parse(s).and_then(|c| TargetGuard::new(vec![c], vec![]));
            assert!(r.is_err(), "allow entry {s:?} should be refused");
        }
        for (input, shown) in &v.good_cidr {
            assert_eq!(Cidr::parse(input).expect(input).to_string(), *shown);
        }
    }

    #[test]
    fn both_lists_are_required_and_a_bad_deny_line_refuses() {
        let dir = testsrv::tempdir();
        let empty = dir.join("empty");
        std::fs::write(&empty, "# nothing denied\n\n").expect("write");
        let bad = dir.join("bad");
        std::fs::write(&bad, "203.0.113.0/24\nrelay.example.com\n").expect("write");
        let allow = vec!["127.0.0.0/8".to_string()];
        assert!(TargetGuard::from_args(&[], Some(&empty)).is_err());
        assert!(TargetGuard::from_args(&allow, None).is_err());
        assert!(TargetGuard::from_args(&allow, Some(&dir.join("missing"))).is_err());
        let err = TargetGuard::from_args(&allow, Some(&bad)).expect_err("bad line");
        assert!(format!("{err:#}").contains("line 2"), "{err:#}");
        TargetGuard::from_args(&allow, Some(&empty)).expect("empty deny list is fine");
    }

    #[test]
    fn join_keeps_the_checked_address() {
        let g = TargetGuard::new(cidrs(&["127.0.0.0/8".into()]), vec![]).expect("guard");
        let base = g
            .check_url("http://127.0.0.1:3030", &["http"])
            .expect("base");
        assert_eq!(
            base.join("/media/upload").expect("join").as_str(),
            "http://127.0.0.1:3030/media/upload"
        );
        for bad in ["media", "/x?y", "/x#y", "/@evil", "/%2e"] {
            assert!(base.join(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_http_client_resolves_no_names() {
        let client = http_client(Duration::from_secs(5)).expect("client");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let err = rt
            .block_on(async {
                client
                    .inner()
                    .get("http://relay.example.com:3030/")
                    .send()
                    .await
            })
            .expect_err("no DNS");
        assert!(format!("{err:?}").contains("resolves no names"), "{err:?}");
    }

    /// A 302 from an allowed address to a denied one is returned, not
    /// followed, through the production upload path.
    #[test]
    fn media_upload_does_not_follow_a_redirect() {
        let denied = Server::start("[::1]:0", testsrv::status(200, "{}"));
        let first = Server::start(
            "127.0.0.1:0",
            testsrv::redirect_to(&format!("{}/x", denied.http())),
        );
        let g = TargetGuard::new(cidrs(&["127.0.0.0/8".into()]), cidrs(&["::1".into()]))
            .expect("guard");
        let base = g.check_url(&first.http(), &["http"]).expect("allowed");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let client = http_client(Duration::from_secs(5)).expect("client");
        let keys = nostr::Keys::generate();
        let Err(err) = rt.block_on(super::super::media::upload(
            &client,
            &base,
            &keys,
            vec![7; 64],
            None,
        )) else {
            panic!("a 302 is not success");
        };
        assert!(format!("{err:#}").contains("302"), "{err:#}");
        assert!(first.accepts() >= 1);
        assert_eq!(denied.accepts(), 0, "the redirect was followed");
    }

    const PROXY_CHILD: &str = "sim::guard::tests::the_http_client_ignores_proxy_variables";

    /// The environment's proxy variables are ignored: the upload goes
    /// straight to the target and the proxy sees nothing.
    #[test]
    fn the_http_client_ignores_proxy_variables() {
        if testsrv::is_child(PROXY_CHILD) {
            let target = Server::start("127.0.0.1:0", testsrv::status(200, r#"{"url":"x"}"#));
            let g = TargetGuard::new(cidrs(&["127.0.0.0/8".into()]), vec![]).expect("guard");
            let base = g.check_url(&target.http(), &["http"]).expect("allowed");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt");
            let client = http_client(Duration::from_secs(5)).expect("client");
            let keys = nostr::Keys::generate();
            rt.block_on(super::super::media::upload(
                &client,
                &base,
                &keys,
                vec![7; 64],
                None,
            ))
            .expect("upload goes direct");
            assert_eq!(target.accepts(), 1);
            println!("CHILD_OK {PROXY_CHILD}");
            return;
        }
        let proxy = Server::start("127.0.0.1:0", testsrv::status(502, "{}"));
        testsrv::run_child(PROXY_CHILD, &testsrv::proxy_env(&proxy.http()));
        assert_eq!(proxy.accepts(), 0, "the proxy was used");
    }

    /// A connect error caused by the generator running out of files, ports
    /// or buffers is its own; any other connect error is not. Found through
    /// the error's causes, as reqwest wraps it, and in an error's text.
    #[test]
    fn local_exhaustion_is_told_apart() {
        #[derive(Debug)]
        struct Wrapped(std::io::Error);
        impl std::fmt::Display for Wrapped {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "tcp connect error")
            }
        }
        impl std::error::Error for Wrapped {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let emfile = std::io::Error::from_raw_os_error(24);
        let enfile = std::io::Error::from_raw_os_error(23);
        let ports = std::io::Error::from(std::io::ErrorKind::AddrNotAvailable);
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        for (name, e, want) in [
            ("EMFILE", Wrapped(emfile), true),
            ("ENFILE", Wrapped(enfile), true),
            ("no local port", Wrapped(ports), true),
            ("refused", Wrapped(refused), false),
        ] {
            assert_eq!(is_local_exhaustion(&e), want, "{name}");
        }
        assert!(text_is_local_exhaustion(
            "h7 connect: IO error: Too many open files (os error 24)"
        ));
        assert!(!text_is_local_exhaustion(
            "h7 connect: IO error: Connection refused (os error 61)"
        ));
        assert!(!text_is_local_exhaustion(
            "h7 connect: IO error: Connection refused (os error 111)"
        ));
    }
}
