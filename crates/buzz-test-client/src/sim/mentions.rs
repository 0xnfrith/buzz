//! Mentions in channel messages: who tags whom (`["p", <pubkey>]`), and how
//! often.
//!
//! Both come from one measurement, and every use names it: **the
//! operator's own relay: 24 channels, 30 days, an agent-heavy workspace**
//! (1,540 kind-9 messages, 1,271 `p` tags, 15 authors, 14 distinct
//! recipients; counts only). About half of the agents'
//! tags there are reply tags with no `@` in the text; for what a mention
//! costs the relay, both count.
//!
//! - **How many messages carry a tag:** 85% of a human's, 77% of an
//!   agent's.
//! - **Who gets the tags:** the measured rank curve, mapped onto the
//!   population. The population in team order (each human, then that
//!   human's agents):
//!   - **the tail:** the last `ceil(2/15)` of the humans and of the agents
//!     are never mentioned ("2 of the 15 authors were never tagged");
//!   - **the head:** ranks 1 to 6 get 22.9, 22.7, 18.7, 10.5, 9.0 and 8.3%
//!     of the tags; rank 1 is the first human, ranks 2 to 6 the next
//!     identities in team order;
//!   - **the middle:** everyone else shares the last 7.9% evenly.
//!
//!   Ranks the population is too small for are left out, and the rest
//!   renormalized. No one mentions themselves.
//!
//! A never-mentioned human's home-feed poll walks every event (see
//! `feed.rs`): an even spread would give every human a cheap poll and size
//! a box too small.

use rand::rngs::StdRng;
use serde::Serialize;

use super::identity::Population;
use super::roles::{rng_f64, Role};

/// Where every use of these numbers says they come from.
pub const SOURCE: &str = "the operator's own relay: 24 channels, 30 days, an agent-heavy workspace";
/// The share of a human's kind-9 messages that carry a `p` tag.
pub const HUMAN_SHARE: f64 = 0.85;
/// The share of an agent's kind-9 messages that carry a `p` tag.
pub const AGENT_SHARE: f64 = 0.77;
/// Ranks 1 to 6's shares of the tags, in %.
pub const HEAD: [f64; 6] = [22.9, 22.7, 18.7, 10.5, 9.0, 8.3];
/// The rest, shared evenly by the middle, in %.
pub const MIDDLE: f64 = 7.9;
/// The never-mentioned share of each role: 2 of 15.
pub const TAIL: (usize, usize) = (2, 15);

/// One identity's place in the model, as `mentions.json` lists it.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Recipient {
    pub name: String,
    pub pubkey: String,
    pub role: String,
    /// 1 to 6 for the head; None for the middle and the tail.
    pub rank: Option<usize>,
    /// Its share of all tags, 0 to 1; 0 for the tail.
    pub share: f64,
    pub tail: bool,
}

/// The model for one population.
#[derive(Clone, Debug)]
pub struct Mentions {
    pub recipients: Vec<Recipient>,
    /// Running totals of the shares, for a weighted pick.
    cumulative: Vec<f64>,
}

/// `ceil(n * 2 / 15)`.
fn tail_of(n: usize) -> usize {
    (n * TAIL.0).div_ceil(TAIL.1)
}

impl Mentions {
    pub fn new(pop: &Population) -> Self {
        // Team order: each human, then its agents.
        let mut order = Vec::new();
        for h in &pop.humans {
            order.push(h);
            order.extend(
                pop.agents
                    .iter()
                    .filter(|a| a.owner_name.as_deref() == Some(h.name.as_str())),
            );
        }
        order.extend(pop.agents.iter().filter(|a| {
            !pop.humans
                .iter()
                .any(|h| a.owner_name.as_deref() == Some(h.name.as_str()))
        }));
        let is_human =
            |r: &&super::identity::IdentityRecord| pop.humans.iter().any(|h| h.pubkey == r.pubkey);
        // The tail: the last ceil(2/15) of each role, in team order.
        let mut tail = std::collections::HashSet::new();
        for human in [true, false] {
            let of_role: Vec<_> = order.iter().filter(|r| is_human(r) == human).collect();
            for r in of_role.iter().rev().take(tail_of(of_role.len())) {
                tail.insert(r.pubkey.clone());
            }
        }
        // The head: rank 1 the first human not in the tail, ranks 2 to 6
        // the next in team order.
        let mut head: Vec<String> = Vec::new();
        if let Some(first) = order
            .iter()
            .find(|r| is_human(r) && !tail.contains(&r.pubkey))
        {
            head.push(first.pubkey.clone());
        }
        for r in &order {
            if head.len() == HEAD.len() {
                break;
            }
            if !tail.contains(&r.pubkey) && !head.contains(&r.pubkey) {
                head.push(r.pubkey.clone());
            }
        }
        let middle: Vec<_> = order
            .iter()
            .filter(|r| !tail.contains(&r.pubkey) && !head.contains(&r.pubkey))
            .collect();
        let mut recipients: Vec<Recipient> = order
            .iter()
            .map(|r| {
                let rank = head.iter().position(|p| *p == r.pubkey);
                let share = match rank {
                    Some(i) => HEAD[i],
                    None if tail.contains(&r.pubkey) => 0.0,
                    None => MIDDLE / middle.len() as f64,
                };
                Recipient {
                    name: r.name.clone(),
                    pubkey: r.pubkey.clone(),
                    role: r.role.clone(),
                    rank: rank.map(|i| i + 1),
                    share,
                    tail: tail.contains(&r.pubkey),
                }
            })
            .collect();
        let total: f64 = recipients.iter().map(|r| r.share).sum();
        if total > 0.0 {
            for r in &mut recipients {
                r.share /= total;
            }
        }
        let mut cumulative = Vec::with_capacity(recipients.len());
        let mut sum = 0.0;
        for r in &recipients {
            sum += r.share;
            cumulative.push(sum);
        }
        Self {
            recipients,
            cumulative,
        }
    }

    /// The share of `role`'s messages that carry a tag.
    pub fn share_of(role: Role) -> f64 {
        match role {
            Role::Human => HUMAN_SHARE,
            Role::Agent => AGENT_SHARE,
        }
    }

    /// The recipient for a message `author` writes, if it carries a tag:
    /// `u` and `v` are two uniform draws in [0, 1), the first for whether
    /// it does, the second for whom. Never the author: a draw that lands on
    /// the author is moved to the next recipient with a share.
    pub fn draw(&self, role: Role, author: &str, u: f64, v: f64) -> Option<&str> {
        if u >= Self::share_of(role) || self.cumulative.is_empty() {
            return None;
        }
        let total = *self.cumulative.last()?;
        let at = v * total;
        let i = self
            .cumulative
            .partition_point(|&c| c <= at)
            .min(self.recipients.len() - 1);
        let n = self.recipients.len();
        (0..n)
            .map(|k| &self.recipients[(i + k) % n])
            .find(|r| r.pubkey != author && r.share > 0.0)
            .map(|r| r.pubkey.as_str())
    }

    /// [`Self::draw`] with an identity's own random numbers.
    pub fn draw_rng(&self, role: Role, author: &str, rng: &mut StdRng) -> Option<String> {
        let (u, v) = (rng_f64(rng), rng_f64(rng));
        self.draw(role, author, u, v).map(str::to_string)
    }

    /// Whether `pubkey` is in the never-mentioned tail.
    pub fn is_tail(&self, pubkey: &str) -> bool {
        self.recipients.iter().any(|r| r.pubkey == pubkey && r.tail)
    }

    /// `mentions.json`: the source and every identity's place.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "source": SOURCE,
            "share": {"human": HUMAN_SHARE, "agent": AGENT_SHARE},
            "recipients": self.recipients,
        })
    }
}

/// Two uniform draws in [0, 1) from a number (splitmix64): the seed's
/// mentions, deterministic per event.
pub fn unit_pair(x: u64) -> (f64, f64) {
    fn mix(mut z: u64) -> u64 {
        z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    let a = mix(x);
    let b = mix(a);
    (
        (a >> 11) as f64 / (1u64 << 53) as f64,
        (b >> 11) as f64 / (1u64 << 53) as f64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::identity::generate_population;
    use rand::SeedableRng;

    fn heavy() -> Population {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../perf/clock-proof/profiles/proof-heavy.toml");
        generate_population(&crate::sim::profile::load_profile(&path).expect("profile"))
    }

    /// Heavy's 25 humans and 75 agents: a never-mentioned tail of 4 humans
    /// and 10 agents, rank 1 a human with 22.9% of the tags, ranks 2 to 6
    /// the measured head, the middle sharing 7.9% evenly.
    #[test]
    fn the_skew_has_a_tail_that_is_never_mentioned() {
        let pop = heavy();
        let m = Mentions::new(&pop);
        let tail_h = m
            .recipients
            .iter()
            .filter(|r| r.tail && pop.humans.iter().any(|h| h.pubkey == r.pubkey))
            .count();
        let tail_a = m.recipients.iter().filter(|r| r.tail).count() - tail_h;
        assert_eq!((tail_h, tail_a), (4, 10));
        assert!(m
            .recipients
            .iter()
            .filter(|r| r.tail)
            .all(|r| r.share == 0.0));
        let head: Vec<(usize, f64)> = m
            .recipients
            .iter()
            .filter_map(|r| r.rank.map(|k| (k, (r.share * 1000.0).round() / 10.0)))
            .collect();
        let mut head = head;
        head.sort_by_key(|(k, _)| *k);
        assert_eq!(
            head,
            vec![
                (1, 22.9),
                (2, 22.7),
                (3, 18.7),
                (4, 10.5),
                (5, 9.0),
                (6, 8.3)
            ]
        );
        let rank1 = m
            .recipients
            .iter()
            .find(|r| r.rank == Some(1))
            .expect("rank 1");
        assert_eq!(rank1.pubkey, pop.humans[0].pubkey, "rank 1 is a human");
        let middle: Vec<f64> = m
            .recipients
            .iter()
            .filter(|r| r.rank.is_none() && !r.tail)
            .map(|r| r.share)
            .collect();
        assert_eq!(middle.len(), 100 - 6 - 14);
        assert!(middle.iter().all(|s| (s - 0.079 / 80.0).abs() < 1e-12));

        // In the run: drawn with an identity's own random numbers, the tail
        // never, no one themselves, and rank 1 about 22.9% of the tags.
        let mut rng = StdRng::seed_from_u64(7);
        let author = &pop.agents[5].pubkey;
        let (mut n, mut first) = (0, 0);
        for _ in 0..50_000 {
            if let Some(who) = m.draw_rng(Role::Agent, author, &mut rng) {
                n += 1;
                assert!(!m.is_tail(&who), "a tail identity was tagged");
                assert_ne!(&who, author, "a self-mention");
                first += usize::from(who == rank1.pubkey);
            }
        }
        let share = first as f64 / n as f64;
        assert!((share - 0.229).abs() < 0.01, "rank 1 got {share}");
        assert!((n as f64 / 50_000.0 - AGENT_SHARE).abs() < 0.01);
    }

    /// The share of messages that carry a tag, per role, from the source.
    #[test]
    fn the_shares_are_the_measured_ones() {
        let m = Mentions::new(&heavy());
        let author = &m.recipients[1].pubkey.clone();
        for (role, want) in [(Role::Human, 0.85), (Role::Agent, 0.77)] {
            let mut rng = StdRng::seed_from_u64(11);
            let n = (0..40_000)
                .filter(|_| m.draw_rng(role, author, &mut rng).is_some())
                .count();
            let got = n as f64 / 40_000.0;
            assert!((got - want).abs() < 0.01, "{role:?}: {got}");
        }
        assert_eq!(
            SOURCE,
            "the operator's own relay: 24 channels, 30 days, an agent-heavy workspace"
        );
    }

    /// A draw that lands on its author moves on, to the next identity with
    /// a share: never the author, and never the tail, even when the tail
    /// comes right after the author.
    #[test]
    fn no_one_mentions_themselves() {
        let pop = heavy();
        let m = Mentions::new(&pop);
        let first_tail = m.recipients.iter().position(|r| r.tail).expect("a tail");
        let before_tail = m.recipients[..first_tail]
            .iter()
            .rev()
            .find(|r| r.share > 0.0)
            .expect("one before the tail")
            .pubkey
            .clone();
        for me in [pop.humans[0].pubkey.clone(), before_tail] {
            for k in 0..20_000u64 {
                let v = k as f64 / 20_000.0;
                if let Some(who) = m.draw(Role::Human, &me, 0.0, v) {
                    assert_ne!(who, me, "a self-mention");
                    assert!(!m.is_tail(who), "a tail identity was tagged");
                }
            }
        }
    }
}
