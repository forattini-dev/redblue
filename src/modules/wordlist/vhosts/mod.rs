//! VHost (Virtual Host) Wordlists
//!
//! Comprehensive wordlists for virtual host enumeration, inspired by VHostScan.
//! These wordlists are optimized for discovering hidden virtual hosts on web servers.
//!
//! # Categories
//!
//! - **Cloud Modern**: Cloud provider patterns, SaaS services, modern infrastructure
//! - **Pentest Focused**: Common pentest targets, admin panels, sensitive endpoints
//! - **Common VHosts**: Traditional subdomain patterns used as virtual hosts
//!
//! # Example
//!
//! ```rust,ignore
//! use redblue::modules::wordlist::vhosts::{VHostWordlist, VHostCategory};
//!
//! // Get cloud-modern wordlist
//! let cloud_words = VHostWordlist::get(VHostCategory::CloudModern);
//!
//! // Get all vhosts combined
//! let all_words = VHostWordlist::all();
//! ```

#![allow(dead_code)]

use std::collections::HashSet;

pub mod cloud_modern;
pub mod common_vhosts;
pub mod pentest_focused;

pub use cloud_modern::CLOUD_MODERN;
pub use common_vhosts::COMMON_VHOSTS;
pub use pentest_focused::PENTEST_FOCUSED;
#[cfg(test)]
mod tests;

/// VHost wordlist category
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VHostCategory {
  /// Cloud provider patterns, SaaS services (~1200 entries)
  CloudModern,
  /// Pentesting targets, admin panels (~600 entries)
  PentestFocused,
  /// Traditional vhost patterns (~800 entries)
  CommonVHosts,
}

/// VHost wordlist provider
pub struct VHostWordlist;

impl VHostWordlist {
  /// Get wordlist for specific category
  pub fn get(category: VHostCategory) -> Vec<&'static str> {
    match category {
      VHostCategory::CloudModern => CLOUD_MODERN.to_vec(),
      VHostCategory::PentestFocused => PENTEST_FOCUSED.to_vec(),
      VHostCategory::CommonVHosts => COMMON_VHOSTS.to_vec(),
    }
  }

  /// Get all wordlists combined (deduplicated)
  pub fn all() -> Vec<&'static str> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for word in CLOUD_MODERN
      .iter()
      .chain(PENTEST_FOCUSED.iter())
      .chain(COMMON_VHOSTS.iter())
    {
      if seen.insert(*word) {
        result.push(*word);
      }
    }

    result
  }

  /// Get wordlist count for category
  pub fn count(category: VHostCategory) -> usize {
    match category {
      VHostCategory::CloudModern => CLOUD_MODERN.len(),
      VHostCategory::PentestFocused => PENTEST_FOCUSED.len(),
      VHostCategory::CommonVHosts => COMMON_VHOSTS.len(),
    }
  }

  /// Get total unique count
  pub fn total_count() -> usize {
    Self::all().len()
  }
}
