//! Agent per-turn reads: what an agent harness reads from the relay on each
//! turn, over the relay's HTTP bridge (`POST /query`, `POST /count`) with
//! NIP-98, as Buzz's own harness does (`buzz-acp`, `relay.rs`: every read
//! goes through `POST /query` with NIP-98 auth).
//!
//! The mix is a default until calibration replaces it. Per turn:
//!
//! 1. the thread's context: the root by id, its replies in the channel
//!    (limit 51), and the agent's own last reply (limit 1), in one query;
//! 2. the profiles of up to 5 authors seen in the channel;
//! 3. the agent's memory: its own kind 30174 events for its owner, limit 16;
//! 4. the channel's recent history, limit 50 (the agent's own tool use);
//! 5. the channel's canvas, limit 1;
//! 6. on one turn in four, a count of the thread's replies.
//!
//! Every filter names its kinds. Reads go to the target guard's checked
//! `--http-url` through the guarded client: no proxy, no redirect, no name.

use std::time::Instant;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::guard::{HttpClient, Target};
use super::profile::KindTable;
use super::stats::ReadFailure;

/// The agent memory kind (NIP-AE engram).
pub const KIND_ENGRAM: u16 = 30174;
/// Stream message v2, read beside the profile's `msg` kind.
pub const KIND_STREAM_MESSAGE_V2: u16 = 40002;
/// One turn in this many also counts the thread's replies.
pub const COUNT_EVERY: u64 = 4;

/// One read: the bridge path, its filters, and a name for the stats.
#[derive(Debug, Clone, PartialEq)]
pub struct Read {
    pub what: &'static str,
    pub path: &'static str,
    pub filters: Value,
}

/// What one turn reads in from: the channel, a root in it (an event seen
/// there), authors seen, and the agent's owner.
pub struct Turn<'a> {
    pub channel: &'a str,
    pub root: Option<&'a str>,
    pub authors: &'a [String],
    pub agent: &'a str,
    pub owner: Option<&'a str>,
    pub n: u64,
}

/// The turn's reads, in the order a harness makes them.
pub fn turn_reads(kinds: &KindTable, t: &Turn<'_>) -> Vec<Read> {
    let msgs = json!([kinds.msg, KIND_STREAM_MESSAGE_V2]);
    let mut out = Vec::new();
    if let Some(root) = t.root {
        out.push(Read {
            what: "thread",
            path: "/query",
            filters: json!([
                {"ids": [root], "kinds": msgs},
                {"kinds": msgs, "#e": [root], "#h": [t.channel], "limit": 51},
                {"kinds": msgs, "#e": [root], "#h": [t.channel], "authors": [t.agent], "limit": 1},
            ]),
        });
    }
    if !t.authors.is_empty() {
        let authors: Vec<&String> = t.authors.iter().take(5).collect();
        out.push(Read {
            what: "profiles",
            path: "/query",
            filters: json!([{"kinds": [0], "authors": authors}]),
        });
    }
    // A harness reads its memory by its own d tag; the stand-in is fixed per
    // agent. The engram gate needs authors=[self].
    let d = hex::encode(Sha256::digest(format!("{}:core", t.agent)));
    let mut memory = json!({"kinds": [KIND_ENGRAM], "authors": [t.agent], "#d": [d], "limit": 16});
    if let Some(owner) = t.owner {
        memory["#p"] = json!([owner]);
    }
    out.push(Read {
        what: "memory",
        path: "/query",
        filters: json!([memory]),
    });
    out.push(Read {
        what: "history",
        path: "/query",
        filters: json!([{"kinds": [kinds.msg], "#h": [t.channel], "limit": 50}]),
    });
    out.push(Read {
        what: "canvas",
        path: "/query",
        filters: json!([{"kinds": [kinds.canvas], "#h": [t.channel], "limit": 1}]),
    });
    if let Some(root) = t.root {
        if t.n.is_multiple_of(COUNT_EVERY) {
            out.push(Read {
                what: "count",
                path: "/count",
                filters: json!([{"kinds": msgs, "#e": [root], "#h": [t.channel]}]),
            });
        }
    }
    out
}

/// Where a read ended.
#[derive(Debug)]
pub enum ReadError {
    /// It failed: where, and why.
    Failed { at: ReadFailure, err: anyhow::Error },
    /// The relay's per-key HTTP rate limit turned it away (429): counted
    /// apart, like a rate-limited send.
    RateLimited,
}

/// `Authorization: Nostr <base64 event>`, NIP-98 for `POST url` with
/// `body`: the `u`, `method`, `payload` and a fresh `nonce` tag (the relay
/// refuses a replayed auth event), signed by `keys`.
pub fn nip98_header(keys: &Keys, url: &str, body: &[u8]) -> Result<String> {
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let tags = [
        Tag::parse(["u", url])?,
        Tag::parse(["method", "POST"])?,
        Tag::parse(["nonce", &nonce])?,
        Tag::parse(["payload", &hex::encode(Sha256::digest(body))])?,
    ];
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .sign_with_keys(keys)?;
    Ok(format!(
        "Nostr {}",
        STANDARD.encode(serde_json::to_string(&event)?)
    ))
}

/// Makes one read and returns how long it took, in ms. An agent admitted
/// through its owner carries its credential in `x-auth-tag`, as for media.
///
/// - Building or signing the request, before it goes out: `Client`, the
///   generator's own error. A request reqwest can't build (a malformed
///   header) is caught here too.
/// - An answer that isn't 2xx, or one that isn't JSON: `Refused`.
/// - No answer, a transport error or a timeout: `Unanswered`.
/// - A 429 the relay's per-key rate limit sends: `RateLimited`, apart.
pub async fn read(
    http: &HttpClient,
    http_url: &Target,
    keys: &Keys,
    auth_tag: Option<&str>,
    r: &Read,
) -> std::result::Result<f64, ReadError> {
    let client = |err: anyhow::Error| ReadError::Failed {
        at: ReadFailure::Client,
        err,
    };
    let url = http_url.join(r.path).map_err(client)?;
    let body = serde_json::to_vec(&r.filters).map_err(|e| client(e.into()))?;
    let auth = nip98_header(keys, url.as_str(), &body).map_err(client)?;
    let mut req = http
        .inner()
        .post(url.as_str())
        .header("Authorization", auth)
        .header("Content-Type", "application/json");
    if let Some(tag) = auth_tag {
        req = req.header("x-auth-tag", tag);
    }
    let start = Instant::now();
    let resp = match req.body(body).send().await {
        Ok(resp) => resp,
        Err(e) if e.is_builder() => return Err(client(anyhow!("{} request: {e}", r.what))),
        Err(e) => {
            return Err(ReadError::Failed {
                at: ReadFailure::Unanswered,
                err: anyhow!("{}: {e}", r.what),
            })
        }
    };
    let status = resp.status();
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            return Err(ReadError::Failed {
                at: ReadFailure::Unanswered,
                err: anyhow!("{} body: {e}", r.what),
            })
        }
    };
    let ms = start.elapsed().as_secs_f64() * 1e3;
    if status.as_u16() == 429 && text.contains("rate-limited") {
        return Err(ReadError::RateLimited);
    }
    if !status.is_success() {
        return Err(ReadError::Failed {
            at: ReadFailure::Refused,
            err: anyhow!("{} HTTP {status}: {text}", r.what),
        });
    }
    if serde_json::from_str::<Value>(&text).is_err() {
        return Err(ReadError::Failed {
            at: ReadFailure::Refused,
            err: anyhow!("{} answered 2xx with a body that isn't JSON", r.what),
        });
    }
    Ok(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::guard::testsrv::{self, Server};
    use crate::sim::guard::{http_client, Cidr, TargetGuard};
    use crate::sim::kinds;
    use std::time::Duration;

    fn target(base: &str) -> Target {
        TargetGuard::new(vec![Cidr::parse("127.0.0.0/8").expect("allow")], vec![])
            .expect("guard")
            .check_url(base, &["http"])
            .expect("allowed")
    }

    fn history() -> Read {
        Read {
            what: "history",
            path: "/query",
            filters: json!([{"kinds": [9], "#h": ["chan-a"], "limit": 50}]),
        }
    }

    async fn one(
        server: &Server,
        timeout: Duration,
        tag: Option<&str>,
    ) -> std::result::Result<f64, ReadError> {
        let http = http_client(timeout).expect("client");
        read(
            &http,
            &target(&server.http()),
            &Keys::generate(),
            tag,
            &history(),
        )
        .await
    }

    fn failed_at(r: std::result::Result<f64, ReadError>) -> (ReadFailure, String) {
        match r {
            Err(ReadError::Failed { at, err }) => (at, format!("{err:#}")),
            other => panic!("not a failure: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_read_the_relay_answers_with_json() {
        let ok = Server::start("127.0.0.1:0", testsrv::status(200, "[]"));
        assert!(one(&ok, Duration::from_secs(5), None).await.is_ok());
        assert_eq!(ok.accepts(), 1);
    }

    /// An answer that isn't 2xx is the relay refusing: a relay break.
    #[tokio::test]
    async fn a_refused_read_is_the_relays() {
        let refusing = Server::start("127.0.0.1:0", testsrv::status(401, r#"{"error":"auth"}"#));
        let (at, err) = failed_at(one(&refusing, Duration::from_secs(5), None).await);
        assert_eq!(at, ReadFailure::Refused, "{err}");
        assert!(err.contains("HTTP 401"), "{err}");
        let garbled = Server::start("127.0.0.1:0", testsrv::status(200, "not json"));
        let (at, err) = failed_at(one(&garbled, Duration::from_secs(5), None).await);
        assert_eq!(
            (at, err.as_str()),
            (
                ReadFailure::Refused,
                "history answered 2xx with a body that isn't JSON"
            )
        );
    }

    /// No answer before the client's timeout is the relay not answering: a
    /// relay break.
    #[tokio::test]
    async fn an_unanswered_read_is_the_relays() {
        let slow = Server::start_after(
            "127.0.0.1:0",
            testsrv::status(200, "[]"),
            Duration::from_secs(3),
        );
        let (at, err) = failed_at(one(&slow, Duration::from_millis(500), None).await);
        assert_eq!(at, ReadFailure::Unanswered, "{err}");
        assert_eq!(slow.accepts(), 1);
    }

    /// A request the generator can't build (here, a credential with a line
    /// break, which no header may hold) is its own error, and nothing goes
    /// out.
    #[tokio::test]
    async fn a_read_the_generator_cant_build_is_its_own() {
        let server = Server::start("127.0.0.1:0", testsrv::status(200, "[]"));
        let (at, err) = failed_at(one(&server, Duration::from_secs(5), Some("bad\ntag")).await);
        assert_eq!(at, ReadFailure::Client, "{err}");
        assert_eq!(server.accepts(), 0, "a request went out");
    }

    /// The relay's per-key HTTP rate limit (429, "rate-limited: ...") is
    /// counted apart; any other 429 is a refusal.
    #[tokio::test]
    async fn a_rate_limited_read_is_apart() {
        let limited = Server::start(
            "127.0.0.1:0",
            testsrv::status(
                429,
                r#"{"error":"rate-limited: quota exceeded; retry in 9s"}"#,
            ),
        );
        assert!(matches!(
            one(&limited, Duration::from_secs(5), None).await,
            Err(ReadError::RateLimited)
        ));
        let other = Server::start("127.0.0.1:0", testsrv::status(429, r#"{"error":"busy"}"#));
        assert_eq!(
            failed_at(one(&other, Duration::from_secs(5), None).await).0,
            ReadFailure::Refused
        );
    }

    /// The header verifies with the relay's own NIP-98 check, for the URL
    /// the relay expects (`http://<host:port>/query`) and the exact body.
    #[test]
    fn the_auth_header_passes_the_relays_nip98_check() {
        let keys = Keys::generate();
        let url = target("http://127.0.0.1:3000").join("/query").expect("url");
        let body = serde_json::to_vec(&history().filters).expect("body");
        let header = nip98_header(&keys, url.as_str(), &body).expect("header");
        let json = String::from_utf8(
            STANDARD
                .decode(header.strip_prefix("Nostr ").expect("prefix"))
                .expect("base64"),
        )
        .expect("utf8");
        let pk = buzz_auth::nip98::verify_nip98_event(
            &json,
            "http://127.0.0.1:3000/query",
            "POST",
            Some(&body),
        )
        .expect("verifies");
        assert_eq!(pk, keys.public_key());
        assert!(
            buzz_auth::nip98::verify_nip98_event(
                &json,
                "http://127.0.0.1:3000/query",
                "POST",
                Some(b"[]")
            )
            .is_err(),
            "another body passed"
        );
        // The relay refuses a replayed auth event by its id: two reads with
        // the same body in the same second must still sign two ids.
        let id = |h: &str| -> String {
            let json = STANDARD
                .decode(h.strip_prefix("Nostr ").expect("prefix"))
                .expect("base64");
            serde_json::from_slice::<Value>(&json).expect("event")["id"]
                .as_str()
                .expect("id")
                .to_string()
        };
        let other = nip98_header(&keys, url.as_str(), &body).expect("header");
        assert_ne!(
            id(&header),
            id(&other),
            "two reads signed the same auth event id"
        );
    }

    /// The default mix: 5 reads a turn, a sixth (the count) on one turn in
    /// four, every filter naming its kinds, none of them p-gated.
    #[test]
    fn the_default_mix() {
        let k = kinds::sample_kinds();
        let authors: Vec<String> = (0..7).map(|i| format!("{i:064x}")).collect();
        let turn = |n| Turn {
            channel: "chan-a",
            root: Some("ee"),
            authors: &authors,
            agent: "aa",
            owner: Some("bb"),
            n,
        };
        let names = |rs: Vec<Read>| rs.iter().map(|r| r.what).collect::<Vec<_>>();
        assert_eq!(
            names(turn_reads(&k, &turn(1))),
            ["thread", "profiles", "memory", "history", "canvas"]
        );
        assert_eq!(
            names(turn_reads(&k, &turn(4))),
            ["thread", "profiles", "memory", "history", "canvas", "count"]
        );
        for r in turn_reads(&k, &turn(4)) {
            for f in r.filters.as_array().expect("filters") {
                let ks = f["kinds"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{} has no kinds", r.what));
                for kind in ks {
                    let kind = kind.as_u64().expect("kind") as u32;
                    assert!(
                        !buzz_core::kind::P_GATED_KINDS.contains(&kind),
                        "{} reads p-gated kind {kind}",
                        r.what
                    );
                }
            }
        }
        let profiles = &turn_reads(&k, &turn(1))[1];
        assert_eq!(
            profiles.filters[0]["authors"]
                .as_array()
                .expect("authors")
                .len(),
            5
        );
        let memory = &turn_reads(&k, &turn(1))[2];
        assert_eq!(
            memory.filters[0]["authors"],
            json!(["aa"]),
            "the engram gate needs authors=[self]"
        );
        let no_root = Turn {
            root: None,
            ..turn(4)
        };
        assert_eq!(
            names(turn_reads(&k, &no_root)),
            ["profiles", "memory", "history", "canvas"]
        );
    }
}
