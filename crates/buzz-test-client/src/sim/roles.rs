//! Duty-cycle helpers: Poisson clocks, burst/idle windows, weighted picks.

use std::time::Duration;

use rand::rngs::StdRng;
use rand::RngExt;

use super::profile::{Profile, Rates};

pub fn rng_f64(rng: &mut StdRng) -> f64 {
    rng.random::<f64>()
}

pub fn rng_usize(rng: &mut StdRng, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (rng_f64(rng) * n as f64).floor() as usize % n
}

/// Exponential inter-arrival for a per-hour Poisson rate.
pub fn poisson_wait(rate_per_hour: f64, rng: &mut StdRng) -> Duration {
    if rate_per_hour <= 0.0 {
        return Duration::from_secs(86_400);
    }
    let lambda = rate_per_hour / 3600.0;
    let u = rng_f64(rng).clamp(1e-12, 1.0);
    let secs = (-u.ln() / lambda).clamp(0.001, 86_400.0);
    Duration::from_secs_f64(secs)
}

pub fn pick_weighted<'a, T>(items: &'a [T], weights: &[f64], rng: &mut StdRng) -> &'a T {
    let sum: f64 = weights.iter().sum();
    let mut x = rng_f64(rng) * sum;
    for (item, w) in items.iter().zip(weights.iter()) {
        if x <= *w {
            return item;
        }
        x -= *w;
    }
    &items[items.len() - 1]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    Warmup,
    Floor,
    Steady,
    Peak,
    Cooldown,
    Stop,
}

impl Band {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "warmup" => Some(Self::Warmup),
            "floor" => Some(Self::Floor),
            "steady" => Some(Self::Steady),
            "peak" => Some(Self::Peak),
            "cooldown" => Some(Self::Cooldown),
            "stop" => Some(Self::Stop),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Floor => "floor",
            Self::Steady => "steady",
            Self::Peak => "peak",
            Self::Cooldown => "cooldown",
            Self::Stop => "stop",
        }
    }

    pub fn sampled(self) -> bool {
        matches!(self, Self::Floor | Self::Steady | Self::Peak)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Human,
    Agent,
}

pub fn scaled_rates(profile: &Profile, role: Role, band: Band) -> Rates {
    let (base, multiplier) = match (role, band) {
        (Role::Human, Band::Peak) => (&profile.human.rates, profile.human.peak_multiplier),
        (Role::Human, _) => (&profile.human.rates, 1.0),
        (Role::Agent, Band::Peak) => (&profile.agent.rates, profile.agent.peak_multiplier),
        (Role::Agent, _) => (&profile.agent.rates, 1.0),
    };
    let scale = |v: f64| v * multiplier;
    match band {
        Band::Floor => Rates {
            presence: match role {
                Role::Human => 3600.0 / profile.human.presence_interval_s.max(1) as f64,
                Role::Agent => base.presence.max(3600.0 / 60.0),
            },
            ..Rates::default()
        },
        Band::Cooldown | Band::Warmup | Band::Stop => Rates::default(),
        Band::Steady | Band::Peak => Rates {
            msg: scale(base.msg),
            reaction: scale(base.reaction),
            edit: scale(base.edit),
            media: scale(base.media),
            dm: scale(base.dm),
            canvas: scale(base.canvas),
            issue: scale(base.issue),
            pr: scale(base.pr),
            git_push: scale(base.git_push),
            turn_metric: scale(base.turn_metric),
            presence: scale(base.presence).max(match role {
                Role::Human => 3600.0 / profile.human.presence_interval_s.max(1) as f64,
                Role::Agent => base.presence,
            }),
        },
    }
}

/// Whether the identity should emit traffic besides presence.
pub fn in_active_window(
    role: Role,
    band: Band,
    elapsed_in_band: Duration,
    profile: &Profile,
) -> bool {
    match (role, band) {
        (_, Band::Floor | Band::Warmup | Band::Cooldown | Band::Stop) => false,
        (Role::Human, Band::Peak) => true,
        (Role::Agent, Band::Peak) if profile.agent.peak_all_active => true,
        (Role::Human, Band::Steady) => {
            let cycle = (profile.human.burst_len_s + profile.human.burst_gap_s).max(1);
            elapsed_in_band.as_secs() % cycle < profile.human.burst_len_s
        }
        (Role::Agent, Band::Steady) | (Role::Agent, Band::Peak) => {
            let cycle = (profile.agent.active_s + profile.agent.idle_s).max(1);
            elapsed_in_band.as_secs() % cycle < profile.agent.active_s
        }
    }
}

pub fn pick_action(rates: &Rates, rng: &mut StdRng) -> Option<&'static str> {
    let entries = rates.entries();
    if entries.is_empty() {
        return None;
    }
    let names: Vec<&'static str> = entries.iter().map(|(n, _)| *n).collect();
    let weights: Vec<f64> = entries.iter().map(|(_, v)| *v).collect();
    Some(*pick_weighted(&names, &weights, rng))
}

pub fn next_any_wait(rates: &Rates, rng: &mut StdRng) -> Duration {
    let total: f64 = rates.entries().iter().map(|(_, v)| *v).sum();
    poisson_wait(total, rng)
}
