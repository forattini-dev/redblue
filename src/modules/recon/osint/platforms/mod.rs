//! Platform definitions for username enumeration
//!
//! Contains 1000+ platform definitions organized by category.

mod business;
mod creative;
mod dating;
mod development;
mod education;
mod finance;
mod gaming;
mod music;
mod news;
mod other;
mod shopping;
mod social;
mod types;
mod video;

pub use types::{DetectionMethod, Platform, PlatformCategory};

use std::collections::HashMap;

/// Get all platforms across all categories
pub fn get_all_platforms() -> Vec<Platform> {
    let mut platforms = Vec::with_capacity(1100);
    platforms.extend(social::get_social_platforms());
    platforms.extend(development::get_development_platforms());
    platforms.extend(gaming::get_gaming_platforms());
    platforms.extend(business::get_business_platforms());
    platforms.extend(creative::get_creative_platforms());
    platforms.extend(music::get_music_platforms());
    platforms.extend(video::get_video_platforms());
    platforms.extend(news::get_news_platforms());
    platforms.extend(education::get_education_platforms());
    platforms.extend(shopping::get_shopping_platforms());
    platforms.extend(dating::get_dating_platforms());
    platforms.extend(finance::get_finance_platforms());
    platforms.extend(other::get_other_platforms());
    platforms
}

/// Get platforms filtered by category
pub fn get_platforms_by_category(category: PlatformCategory) -> Vec<Platform> {
    match category {
        PlatformCategory::Social => social::get_social_platforms(),
        PlatformCategory::Development => development::get_development_platforms(),
        PlatformCategory::Gaming => gaming::get_gaming_platforms(),
        PlatformCategory::Business => business::get_business_platforms(),
        PlatformCategory::Creative => creative::get_creative_platforms(),
        PlatformCategory::Music => music::get_music_platforms(),
        PlatformCategory::Video => video::get_video_platforms(),
        PlatformCategory::News => news::get_news_platforms(),
        PlatformCategory::Education => education::get_education_platforms(),
        PlatformCategory::Shopping => shopping::get_shopping_platforms(),
        PlatformCategory::Dating => dating::get_dating_platforms(),
        PlatformCategory::Finance => finance::get_finance_platforms(),
        PlatformCategory::Photography => Vec::new(),
        PlatformCategory::Forum => Vec::new(),
        PlatformCategory::Crypto => Vec::new(),
        PlatformCategory::Adult => Vec::new(),
        PlatformCategory::Other => other::get_other_platforms(),
    }
}

/// Get a platform by name
pub fn get_platform_by_name(name: &str) -> Option<Platform> {
    get_all_platforms()
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}

/// Get all platform names
pub fn get_platform_names() -> Vec<&'static str> {
    get_all_platforms().iter().map(|p| p.name).collect()
}

/// Count platforms by category
pub fn count_by_category() -> HashMap<PlatformCategory, usize> {
    let mut counts = HashMap::new();
    for platform in get_all_platforms() {
        *counts.entry(platform.category).or_insert(0) += 1;
    }
    counts
}
