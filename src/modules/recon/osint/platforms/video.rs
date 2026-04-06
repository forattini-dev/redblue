//! Video platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all video platforms
pub fn get_video_platforms() -> Vec<Platform> {
  vec![
    Platform {
      name: "YouTube",
      category: PlatformCategory::Video,
      url_pattern: "https://www.youtube.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Vimeo",
      category: PlatformCategory::Video,
      url_pattern: "https://vimeo.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Dailymotion",
      category: PlatformCategory::Video,
      url_pattern: "https://www.dailymotion.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bilibili",
      category: PlatformCategory::Video,
      url_pattern: "https://space.bilibili.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kick",
      category: PlatformCategory::Video,
      url_pattern: "https://kick.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Rumble",
      category: PlatformCategory::Video,
      url_pattern: "https://rumble.com/c/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Odysee",
      category: PlatformCategory::Video,
      url_pattern: "https://odysee.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PeerTube (framatube)",
      category: PlatformCategory::Video,
      url_pattern: "https://framatube.org/a/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Trovo",
      category: PlatformCategory::Video,
      url_pattern: "https://trovo.live/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Niconico",
      category: PlatformCategory::Video,
      url_pattern: "https://www.nicovideo.jp/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kwai",
      category: PlatformCategory::Video,
      url_pattern: "https://www.kwai.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Streamable",
      category: PlatformCategory::Video,
      url_pattern: "https://streamable.com/o/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bitchute",
      category: PlatformCategory::Video,
      url_pattern: "https://www.bitchute.com/channel/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bilibili",
      category: PlatformCategory::Video,
      url_pattern: "https://space.bilibili.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Douyin",
      category: PlatformCategory::Video,
      url_pattern: "https://www.douyin.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "AfreecaTV",
      category: PlatformCategory::Video,
      url_pattern: "https://bj.afreecatv.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Rutube",
      category: PlatformCategory::Video,
      url_pattern: "https://rutube.ru/channel/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Slaati",
      category: PlatformCategory::Video,
      url_pattern: "https://slaati.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "DLive",
      category: PlatformCategory::Video,
      url_pattern: "https://dlive.tv/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Caffeine",
      category: PlatformCategory::Video,
      url_pattern: "https://www.caffeine.tv/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Trovo",
      category: PlatformCategory::Video,
      url_pattern: "https://trovo.live/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Theta.tv",
      category: PlatformCategory::Video,
      url_pattern: "https://www.theta.tv/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Glimesh",
      category: PlatformCategory::Video,
      url_pattern: "https://glimesh.tv/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Picarto",
      category: PlatformCategory::Video,
      url_pattern: "https://picarto.tv/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Nimo TV",
      category: PlatformCategory::Video,
      url_pattern: "https://www.nimo.tv/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Booyah",
      category: PlatformCategory::Video,
      url_pattern: "https://booyah.live/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Nonolive",
      category: PlatformCategory::Video,
      url_pattern: "https://www.nonolive.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bigo Live",
      category: PlatformCategory::Video,
      url_pattern: "https://www.bigo.tv/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "17Live",
      category: PlatformCategory::Video,
      url_pattern: "https://17.live/live/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Uplive",
      category: PlatformCategory::Video,
      url_pattern: "https://www.uplive.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Dailymotion",
      category: PlatformCategory::Video,
      url_pattern: "https://www.dailymotion.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Vimeo",
      category: PlatformCategory::Video,
      url_pattern: "https://vimeo.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Loom",
      category: PlatformCategory::Video,
      url_pattern: "https://www.loom.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Wistia",
      category: PlatformCategory::Video,
      url_pattern: "https://{username}.wistia.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Vidyard",
      category: PlatformCategory::Video,
      url_pattern: "https://share.vidyard.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PeerTube",
      category: PlatformCategory::Video,
      url_pattern: "https://peertube.tv/accounts/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Odysee",
      category: PlatformCategory::Video,
      url_pattern: "https://odysee.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Rumble",
      category: PlatformCategory::Video,
      url_pattern: "https://rumble.com/c/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Brighteon",
      category: PlatformCategory::Video,
      url_pattern: "https://www.brighteon.com/channels/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "UGETube",
      category: PlatformCategory::Video,
      url_pattern: "https://ugetube.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Veoh",
      category: PlatformCategory::Video,
      url_pattern: "https://www.veoh.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Metacafe",
      category: PlatformCategory::Video,
      url_pattern: "https://www.metacafe.com/channels/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ClipChamp",
      category: PlatformCategory::Video,
      url_pattern: "https://clipchamp.com/watch/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kapwing",
      category: PlatformCategory::Video,
      url_pattern: "https://www.kapwing.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Moj",
      category: PlatformCategory::Video,
      url_pattern: "https://mojapp.in/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Josh",
      category: PlatformCategory::Video,
      url_pattern: "https://share.myjosh.in/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Chingari",
      category: PlatformCategory::Video,
      url_pattern: "https://chingari.io/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kwai",
      category: PlatformCategory::Video,
      url_pattern: "https://www.kwai.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
  ]
}
