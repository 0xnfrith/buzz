//! Population generator shared by the `tenant_sim` binary.
#![allow(dead_code, unused_imports)]

pub mod admission;
pub mod git;
pub mod identity;
pub mod kinds;
pub mod media;
pub mod profile;
pub mod roles;
pub mod seed;
pub mod stats;

pub use identity::{generate_population, load_population, save_population, Population};
pub use profile::{load_profile, Profile};
pub use stats::{percentiles, Stats};
