//! Music platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all music platforms
pub fn get_music_platforms() -> Vec<Platform> {
    vec![
        Platform {
            name: "Spotify",
            category: PlatformCategory::Music,
            url_pattern: "https://open.spotify.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "SoundCloud",
            category: PlatformCategory::Music,
            url_pattern: "https://soundcloud.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Last.fm",
            category: PlatformCategory::Music,
            url_pattern: "https://www.last.fm/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Bandcamp",
            category: PlatformCategory::Music,
            url_pattern: "https://{username}.bandcamp.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "MixCloud",
            category: PlatformCategory::Music,
            url_pattern: "https://www.mixcloud.com/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Discogs",
            category: PlatformCategory::Music,
            url_pattern: "https://www.discogs.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Anchor.fm",
            category: PlatformCategory::Music,
            url_pattern: "https://anchor.fm/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Podbean",
            category: PlatformCategory::Music,
            url_pattern: "https://{username}.podbean.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Spreaker",
            category: PlatformCategory::Music,
            url_pattern: "https://www.spreaker.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Castbox",
            category: PlatformCategory::Music,
            url_pattern: "https://castbox.fm/channel/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Deezer",
            category: PlatformCategory::Music,
            url_pattern: "https://www.deezer.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Tidal",
            category: PlatformCategory::Music,
            url_pattern: "https://tidal.com/browse/artist/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Audiomack",
            category: PlatformCategory::Music,
            url_pattern: "https://audiomack.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "ReverbNation",
            category: PlatformCategory::Music,
            url_pattern: "https://www.reverbnation.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "HearThis.at",
            category: PlatformCategory::Music,
            url_pattern: "https://hearthis.at/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "DistroKid",
            category: PlatformCategory::Music,
            url_pattern: "https://distrokid.com/hyperfollow/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Linktree Music",
            category: PlatformCategory::Music,
            url_pattern: "https://linktr.ee/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Genius",
            category: PlatformCategory::Music,
            url_pattern: "https://genius.com/artists/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Songkick",
            category: PlatformCategory::Music,
            url_pattern: "https://www.songkick.com/artists/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Setlist.fm",
            category: PlatformCategory::Music,
            url_pattern: "https://www.setlist.fm/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Mixcloud",
            category: PlatformCategory::Music,
            url_pattern: "https://www.mixcloud.com/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Anchor",
            category: PlatformCategory::Music,
            url_pattern: "https://anchor.fm/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Spotify Podcasters",
            category: PlatformCategory::Music,
            url_pattern: "https://podcasters.spotify.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Podbean",
            category: PlatformCategory::Music,
            url_pattern: "https://{username}.podbean.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Spreaker",
            category: PlatformCategory::Music,
            url_pattern: "https://www.spreaker.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Buzzsprout",
            category: PlatformCategory::Music,
            url_pattern: "https://www.buzzsprout.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Transistor",
            category: PlatformCategory::Music,
            url_pattern: "https://{username}.transistor.fm",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Captivate",
            category: PlatformCategory::Music,
            url_pattern: "https://player.captivate.fm/show/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "RedCircle",
            category: PlatformCategory::Music,
            url_pattern: "https://redcircle.com/shows/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "BeatStars",
            category: PlatformCategory::Music,
            url_pattern: "https://www.beatstars.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Splice",
            category: PlatformCategory::Music,
            url_pattern: "https://splice.com/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Landr",
            category: PlatformCategory::Music,
            url_pattern: "https://www.landr.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Looperman",
            category: PlatformCategory::Music,
            url_pattern: "https://www.looperman.com/users/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Audius",
            category: PlatformCategory::Music,
            url_pattern: "https://audius.co/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Udio",
            category: PlatformCategory::Music,
            url_pattern: "https://www.udio.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Suno",
            category: PlatformCategory::Music,
            url_pattern: "https://suno.com/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "SoundCloud",
            category: PlatformCategory::Music,
            url_pattern: "https://soundcloud.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Spotify",
            category: PlatformCategory::Music,
            url_pattern: "https://open.spotify.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Last.fm",
            category: PlatformCategory::Music,
            url_pattern: "https://www.last.fm/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Bandcamp",
            category: PlatformCategory::Music,
            url_pattern: "https://{username}.bandcamp.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Apple Music",
            category: PlatformCategory::Music,
            url_pattern: "https://music.apple.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Rate Your Music",
            category: PlatformCategory::Music,
            url_pattern: "https://rateyourmusic.com/~{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Discogs",
            category: PlatformCategory::Music,
            url_pattern: "https://www.discogs.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Album of the Year",
            category: PlatformCategory::Music,
            url_pattern: "https://www.albumoftheyear.org/user/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "ListenBrainz",
            category: PlatformCategory::Music,
            url_pattern: "https://listenbrainz.org/user/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "MusicBrainz",
            category: PlatformCategory::Music,
            url_pattern: "https://musicbrainz.org/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "JioSaavn",
            category: PlatformCategory::Music,
            url_pattern: "https://www.jiosaavn.com/artist/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Gaana",
            category: PlatformCategory::Music,
            url_pattern: "https://gaana.com/artist/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Wynk",
            category: PlatformCategory::Music,
            url_pattern: "https://wynk.in/music/artist/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Anchor",
            category: PlatformCategory::Music,
            url_pattern: "https://anchor.fm/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Podbean",
            category: PlatformCategory::Music,
            url_pattern: "https://{username}.podbean.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Transistor",
            category: PlatformCategory::Music,
            url_pattern: "https://{username}.transistor.fm",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Spreaker",
            category: PlatformCategory::Music,
            url_pattern: "https://www.spreaker.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Buzzsprout",
            category: PlatformCategory::Music,
            url_pattern: "https://www.buzzsprout.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Pocketcasts",
            category: PlatformCategory::Music,
            url_pattern: "https://pca.st/podcast/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
    ]
}
