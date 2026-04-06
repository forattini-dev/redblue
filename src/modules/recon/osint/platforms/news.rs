//! News platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all news platforms
pub fn get_news_platforms() -> Vec<Platform> {
  vec![
    Platform {
      name: "Quora",
      category: PlatformCategory::News,
      url_pattern: "https://www.quora.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hacker News",
      category: PlatformCategory::News,
      url_pattern: "https://news.ycombinator.com/user?id={username}",
      detection: DetectionMethod::ResponseNotContains {
        text: "No such user".to_string(),
      },
      ..Default::default()
    },
    Platform {
      name: "Substack",
      category: PlatformCategory::News,
      url_pattern: "https://{username}.substack.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Yandex Zen",
      category: PlatformCategory::News,
      url_pattern: "https://zen.yandex.ru/id/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mirror.xyz",
      category: PlatformCategory::News,
      url_pattern: "https://mirror.xyz/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Substack",
      category: PlatformCategory::News,
      url_pattern: "https://{username}.substack.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ghost",
      category: PlatformCategory::News,
      url_pattern: "https://{username}.ghost.io",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Revue",
      category: PlatformCategory::News,
      url_pattern: "https://www.getrevue.co/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Buttondown",
      category: PlatformCategory::News,
      url_pattern: "https://buttondown.email/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Beehiiv",
      category: PlatformCategory::News,
      url_pattern: "https://{username}.beehiiv.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ConvertKit",
      category: PlatformCategory::News,
      url_pattern: "https://{username}.ck.page",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Yandex Zen",
      category: PlatformCategory::News,
      url_pattern: "https://zen.yandex.ru/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
  ]
}
