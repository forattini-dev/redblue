//! Social platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

mod social_community;
mod social_core;
mod social_misc;

/// Get all social platforms
pub fn get_social_platforms() -> Vec<Platform> {
  let mut platforms = Vec::new();

  platforms.extend(social_core::platforms());
  platforms.extend(social_community::platforms());
  platforms.extend(social_misc::platforms());

  platforms
}
