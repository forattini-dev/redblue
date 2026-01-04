//! Dating platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all dating platforms
pub fn get_dating_platforms() -> Vec<Platform> {
    vec![
        Platform {
            name: "OkCupid",
            category: PlatformCategory::Dating,
            url_pattern: "https://www.okcupid.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "PlentyOfFish",
            category: PlatformCategory::Dating,
            url_pattern: "https://www.pof.com/viewprofile.aspx?profile_id={username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "OkCupid",
            category: PlatformCategory::Dating,
            url_pattern: "https://www.okcupid.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "PlentyOfFish",
            category: PlatformCategory::Dating,
            url_pattern: "https://www.pof.com/viewprofile.aspx?profile_id={username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Bumble",
            category: PlatformCategory::Dating,
            url_pattern: "https://bumble.com/en/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Hinge",
            category: PlatformCategory::Dating,
            url_pattern: "https://hinge.co/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Badoo",
            category: PlatformCategory::Dating,
            url_pattern: "https://badoo.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Match",
            category: PlatformCategory::Dating,
            url_pattern: "https://www.match.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Zoosk",
            category: PlatformCategory::Dating,
            url_pattern: "https://www.zoosk.com/personals/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
    ]
}
